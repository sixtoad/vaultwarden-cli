fn main() {
    let result = (|| {
        let executable =
            std::env::current_exe().map_err(|_| "Cannot locate launcher".to_owned())?;
        let command = executable
            .file_stem()
            .and_then(|n| n.to_str())
            .ok_or("Invalid launcher name".to_owned())?;
        companion_core::installation::launch(command, &executable, std::env::args_os().skip(1))
    })();
    match result {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
