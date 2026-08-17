//! `cargo hyperscale`: scaffold a package, build one, or check one.
//!
//! `build` is the whole pipeline — the code, the declaration, the
//! artifact, and the publish gate's verdict on it — and `check` is the
//! same without the write. That the local verdict and the chain's are one
//! call is the point of the command: a package that checks clean here has
//! passed exactly what admission runs.

use std::path::{Path, PathBuf};
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

/// Where a scaffolded package finds the SDK.
///
/// A path while the SDK is unpublished, resolved against the new crate's
/// own location so the scaffold works from anywhere in the repository.
fn sdk_dependency(dir: &Path) -> String {
    let sdk = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|crates| crates.join("sdk"));
    sdk.map_or_else(
        || "\"0.1\"".to_owned(),
        |sdk| format!("{{ path = \"{}\" }}", relative(dir, &sdk).display()),
    )
}

/// `sdk` as reached from `dir`, falling back to the absolute path where
/// the two share no root worth walking.
///
/// Sharing only `/` is not sharing anything: the relative form would be a
/// run of `..` as long as the path it replaces, and an absolute one at
/// least reads.
fn relative(dir: &Path, sdk: &Path) -> PathBuf {
    let Ok(from) = dir.canonicalize() else {
        return sdk.to_path_buf();
    };
    let shared = from
        .components()
        .zip(sdk.components())
        .take_while(|(a, b)| a == b)
        .count();
    if shared <= 1 {
        return sdk.to_path_buf();
    }
    let mut path = PathBuf::new();
    for _ in shared..from.components().count() {
        path.push("..");
    }
    path.extend(sdk.components().skip(shared));
    path
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
            scaffold::package(&dir, &sdk_dependency(&dir))?;
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
