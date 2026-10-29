//! Local filesystem installation only; separate from provider authority.
pub fn inspect_installation(root: String, path: String) -> Result<String, String> {
    serde_json::to_string(&crate::installation::inspect(
        std::path::Path::new(&root),
        &path,
    ))
    .map_err(|_| "Cannot report installation".to_owned())
}
pub fn enable_commands(root: String, directory: String) -> Result<String, String> {
    crate::installation::enable(
        std::path::Path::new(&root),
        std::path::Path::new(&directory),
    )
}
