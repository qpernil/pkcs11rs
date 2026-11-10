use std::{
    env,
    path::{Path, PathBuf},
    process::{self, Command},
};

const RELATED_PROJECTS: [&str; 7] = [
    "software-key-core",
    "virtual-yubikey",
    "virtual-yubihsm",
    "usb-gadget-supervisor",
    "display-backends",
    "raspberry-pi-i2c-target",
    "swedish-tax",
];

/// Check selected workspaces without changing manifests or lockfiles.
pub(super) fn check(args: &[String]) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask directory has a parent");
    let cwd = env::current_dir().expect("current working directory");
    let manifests = selected_manifests(root, &cwd, args).unwrap_or_else(|| super::usage());
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut failures = 0;
    for manifest in &manifests {
        if !manifest.is_file() {
            eprintln!("\nFAILED: missing manifest {}", manifest.display());
            failures += 1;
            continue;
        }
        let directory = manifest.parent().expect("manifest has a parent");
        let policy = policy_for(manifest, root);
        eprintln!("\nAvailable dependency updates: {}", manifest.display());
        let update = Command::new(&cargo)
            .current_dir(directory)
            .arg("update")
            .arg("--manifest-path")
            .arg(manifest)
            .args(["--dry-run", "--verbose"])
            .status();
        let update_ok = succeeded(update, "dependency update inspection");

        eprintln!(
            "\nLocked advisory and license checks: {}",
            manifest.display()
        );
        eprintln!("Policy: {} (including its exceptions)", policy.display());
        let check = Command::new(&cargo)
            .current_dir(directory)
            .arg("deny")
            .arg("--manifest-path")
            .arg(manifest)
            .args(["--workspace", "--all-features", "--locked", "--config"])
            .arg(&policy)
            .args(["check", "advisories", "licenses"])
            .status();
        let policy_ok = succeeded(check, "dependency policy check (requires cargo-deny)");
        let passed = update_ok && policy_ok;
        eprintln!(
            "{}: {}",
            if passed { "PASS" } else { "FAILED" },
            manifest.display()
        );
        failures += usize::from(!passed);
    }
    eprintln!(
        "\nDependency review: {} passed, {failures} failed.",
        manifests.len() - failures,
    );
    if failures != 0 {
        process::exit(1);
    }
}

fn selected_manifests(root: &Path, cwd: &Path, args: &[String]) -> Option<Vec<PathBuf>> {
    let mut all = false;
    let mut extra = Vec::new();
    let mut args = args.iter();
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--check" => {}
            "--all" => all = true,
            "--manifest-path" => {
                let argument = args.next()?;
                if argument.is_empty() || argument.starts_with('-') {
                    return None;
                }
                extra.push(cwd.join(argument));
            }
            _ => return None,
        }
    }
    let mut manifests = Vec::new();
    if all || extra.is_empty() {
        manifests.push(root.join("Cargo.toml"));
        manifests.push(root.join("xtask/Cargo.toml"));
    }
    if all {
        let parent = root.parent()?;
        manifests.extend(RELATED_PROJECTS.map(|project| parent.join(project).join("Cargo.toml")));
    }
    manifests.extend(extra);
    let mut unique = Vec::new();
    for manifest in manifests {
        let manifest = manifest.canonicalize().unwrap_or(manifest);
        if !unique.contains(&manifest) {
            unique.push(manifest);
        }
    }
    Some(unique)
}

fn policy_for(manifest: &Path, root: &Path) -> PathBuf {
    manifest
        .parent()
        .into_iter()
        .flat_map(Path::ancestors)
        .map(|directory| directory.join("deny.toml"))
        .find(|policy| policy.is_file())
        .unwrap_or_else(|| root.join("deny.toml"))
}

fn succeeded(result: std::io::Result<process::ExitStatus>, description: &str) -> bool {
    match result {
        Ok(status) if status.success() => true,
        Ok(status) => {
            eprintln!("{description} failed: {status}");
            false
        }
        Err(error) => {
            eprintln!("Could not run {description}: {error}");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn all_adds_known_projects_and_preserves_explicit_selections() {
        let root = Path::new("/fixture/projects/pkcs11rs");
        let cwd = Path::new("/fixture/projects");
        let selected = selected_manifests(
            root,
            cwd,
            &args(&["--all", "--manifest-path", "new-project/Cargo.toml"]),
        )
        .unwrap();
        assert_eq!(selected.len(), 10);
        assert!(selected.contains(&root.join("xtask/Cargo.toml")));
        assert!(selected.contains(&cwd.join("software-key-core/Cargo.toml")));
        assert!(selected.contains(&cwd.join("swedish-tax/Cargo.toml")));
        assert!(selected.contains(&cwd.join("new-project/Cargo.toml")));
    }

    #[test]
    fn explicit_manifest_is_relative_to_the_calling_directory() {
        let selected = selected_manifests(
            Path::new("/fixture/pkcs11rs"),
            Path::new("/fixture/other"),
            &args(&[
                "--manifest-path",
                "Cargo.toml",
                "--manifest-path",
                "Cargo.toml",
            ]),
        )
        .unwrap();
        assert_eq!(selected, [Path::new("/fixture/other/Cargo.toml")]);
    }

    #[test]
    fn invalid_update_modes_and_missing_paths_are_rejected() {
        for values in [
            vec!["--update"],
            vec!["--manifest-path"],
            vec!["--manifest-path", "--all"],
            vec!["--manifest-path", "--update"],
            vec!["--manifest-path", ""],
        ] {
            assert!(
                selected_manifests(
                    Path::new("/fixture/pkcs11rs"),
                    Path::new("/fixture"),
                    &args(&values)
                )
                .is_none()
            );
        }
    }
}
