use std::ffi::CString;

fn select_reader(context: &pcsc::Context) -> Result<CString, String> {
    let readers = context
        .list_readers_owned()
        .map_err(|error| format!("failed to list PC/SC readers: {error}"))?;
    let requested = std::env::args().nth(1);
    if let Some(requested) = requested {
        let matches = readers
            .into_iter()
            .filter(|reader| reader.to_string_lossy() == requested)
            .collect::<Vec<_>>();
        return match matches.as_slice() {
            [reader] => Ok(reader.clone()),
            [] => Err(format!("no PC/SC reader is named {requested:?}")),
            _ => Err(format!("more than one PC/SC reader is named {requested:?}")),
        };
    }
    match readers.as_slice() {
        [reader] => Ok(reader.clone()),
        [] => Err("expected one PC/SC reader with one inserted card, found none".to_owned()),
        readers => Err(format!(
            "expected exactly one PC/SC reader; found {} (pass its exact name to select one)",
            readers.len()
        )),
    }
}

fn run() -> Result<(), String> {
    let context = pcsc::Context::establish(pcsc::Scope::System)
        .map_err(|error| format!("failed to establish PC/SC context: {error}"))?;
    let reader = select_reader(&context)?;
    let protocols = pcsc::Protocols::T0 | pcsc::Protocols::T1;
    let exclusive = context
        .connect(&reader, pcsc::ShareMode::Exclusive, protocols)
        .map_err(|error| {
            format!(
                "failed to connect exclusively to {:?}: {error}",
                reader.to_string_lossy()
            )
        })?;

    let peer_context = pcsc::Context::establish(pcsc::Scope::System)
        .map_err(|error| format!("failed to establish peer PC/SC context: {error}"))?;
    match peer_context.connect(&reader, pcsc::ShareMode::Shared, protocols) {
        Err(pcsc::Error::SharingViolation) => {}
        Err(error) => {
            return Err(format!(
                "peer connection failed with {error}, expected a sharing violation"
            ));
        }
        Ok(peer) => {
            let _ = peer.disconnect(pcsc::Disposition::LeaveCard);
            return Err("peer connected while the exclusive connection was alive".to_owned());
        }
    }

    exclusive
        .disconnect(pcsc::Disposition::LeaveCard)
        .map_err(|(_, error)| format!("failed to release exclusive connection: {error}"))?;
    let peer = peer_context
        .connect(&reader, pcsc::ShareMode::Shared, protocols)
        .map_err(|error| format!("peer could not connect after exclusive release: {error}"))?;
    peer.disconnect(pcsc::Disposition::LeaveCard)
        .map_err(|(_, error)| format!("failed to release peer connection: {error}"))?;

    println!(
        "PASS: {:?} rejected a peer while held exclusively and accepted it after release",
        reader.to_string_lossy()
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("FAIL: {error}");
        std::process::exit(1);
    }
}
