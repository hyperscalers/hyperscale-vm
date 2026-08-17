//! `cargo hyperscale`: scaffold a package, build one, or check one.
//!
//! `build` is the whole pipeline — the code, the declaration, the
//! artifact, and the publish gate's verdict on it — and `check` is the
//! same without the write. That the local verdict and the chain's are one
//! call is the point of the command: a package that checks clean here has
//! passed exactly what admission runs.

use std::path::PathBuf;
use std::process::ExitCode;

use hyperscale_vm_cli::{BuildError, Provenance, artifact, artifact_path, build, scaffold};

const USAGE: &str = "\
cargo hyperscale — build a package crate into an artifact the chain admits

    cargo hyperscale new <path>   scaffold a package crate
    cargo hyperscale build [dir]  build, attach, and admit; writes the artifact
    cargo hyperscale check [dir]  the same verdict, without the write

`dir` defaults to the current directory. Pass `--protocol` to build under
the gate genesis seeds a package through, which is the only one that
admits a claim to totality.
";

fn main() -> ExitCode {
    // Invoked as `cargo hyperscale …`, cargo passes its own subcommand
    // name through as the first argument; invoked directly it does not.
    let args: Vec<String> = std::env::args()
        .skip(1)
        .skip_while(|arg| arg == "hyperscale")
        .collect();
    match run(&args) {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<String, BuildError> {
    let command = args.first().map(String::as_str);
    let protocol = args.iter().any(|arg| arg == "--protocol");
    let provenance = if protocol {
        Provenance::Protocol
    } else {
        Provenance::Published
    };
    let target = || -> PathBuf {
        args.iter()
            .skip(1)
            .find(|arg| !arg.starts_with("--"))
            .map_or_else(|| PathBuf::from("."), PathBuf::from)
    };
    match command {
        Some("new") => {
            let dir = args
                .get(1)
                .ok_or_else(|| BuildError("`new` takes the path to create".into()))?;
            let dir = PathBuf::from(dir);
            // Created before the SDK path is worked out, so the relative
            // form can be taken against somewhere that exists.
            std::fs::create_dir_all(&dir)
                .map_err(|error| BuildError(format!("create {}: {error}", dir.display())))?;
            scaffold::package(&dir)?;
            Ok(format!(
                "scaffolded {}\n    cargo hyperscale check {}",
                dir.display(),
                dir.display()
            ))
        }
        Some("build") => {
            let path = build(&target(), provenance)?;
            let bytes = std::fs::metadata(&path).map_or(0, |file| file.len());
            Ok(format!("wrote {} ({bytes} bytes)", path.display()))
        }
        Some("check") => {
            let bytes = artifact(&target(), provenance)?;
            Ok(format!(
                "admitted ({} bytes, unwritten — `build` writes {})",
                bytes.len(),
                artifact_path(&target()).display()
            ))
        }
        _ => Err(BuildError(USAGE.to_owned())),
    }
}
