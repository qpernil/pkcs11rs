impl Command {
    pub(crate) fn get_log_entries() -> Self {
        Self::empty(CommandCode::GetLogEntries)
    }

    pub(crate) fn set_log_index(index: u16) -> Self {
        Self {
            code: CommandCode::SetLogIndex,
            data: Zeroizing::new(index.to_be_bytes().to_vec()),
        }
    }
}
