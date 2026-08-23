//! `cargo hyperscale`: scaffold a package, build one, check one, or read
//! what one declares.
//!
//! `build` is the whole pipeline — the code, the declaration, the
//! artifact, and the publish gate's verdict on it — and `check` is the
//! same without the write. That the local verdict and the chain's are one
//! call is the point of the command: a package that checks clean here has
//! passed exactly what admission runs.
//!
//! `explain` reads the other half. A declaration is derived from the
//! bodies rather than written down, so an author's own package is the one
//! thing they cannot see — and the same host build the other commands run
//! is what produces it, so there is nothing to reimplement.

use std::path::PathBuf;
use std::process::ExitCode;

use hyperscale_vm_cli::{
    BuildError, Provenance, artifact, artifact_path, build, declaration, explain, explain_method,
    scaffold,
};

const USAGE: &str = "\
cargo hyperscale — build a package crate into an artifact the chain admits

    cargo hyperscale new <path>      scaffold a package crate
    cargo hyperscale build [dir]     build, attach, and admit; writes the artifact
    cargo hyperscale check [dir]     the same verdict, without the write
    cargo hyperscale explain [dir]   print what the package declares

`dir` defaults to the current directory. Pass `--protocol` to build under
the gate genesis seeds a package through, which is the only one that
admits a claim to totality. Pass `--method <name>` to `explain` to print
one method rather than the whole package.
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

/// One command line, read once.
///
/// Parsed up front rather than scanned per question, because a flag that
/// takes a value makes the two indistinguishable to a scan: `--method
/// swap` would otherwise offer `swap` as the directory to whatever looked
/// for the first argument that is not a flag.
struct Invocation {
    command: Option<String>,
    /// The arguments that are not flags and not the command, in order.
    positional: Vec<String>,
    protocol: bool,
    method: Option<String>,
}

impl Invocation {
    /// Read `args`, refusing a flag whose value is missing.
    fn read(args: &[String]) -> Result<Self, BuildError> {
        let mut invocation = Self {
            command: args.first().cloned(),
            positional: Vec::new(),
            protocol: false,
            method: None,
        };
        let mut rest = args.iter().skip(1);
        while let Some(arg) = rest.next() {
            match arg.as_str() {
                "--protocol" => invocation.protocol = true,
                "--method" => {
                    invocation.method = Some(
                        rest.next()
                            .ok_or_else(|| BuildError("`--method` takes a name".into()))?
                            .clone(),
                    );
                }
                flag if flag.starts_with("--") => {
                    return Err(BuildError(format!("{flag}: no such option")));
                }
                value => invocation.positional.push(value.to_owned()),
            }
        }
        Ok(invocation)
    }

    /// The package directory, defaulting to where the command was run.
    fn target(&self) -> PathBuf {
        self.positional
            .first()
            .map_or_else(|| PathBuf::from("."), PathBuf::from)
    }

    /// Which gate the artifact is built under.
    const fn provenance(&self) -> Provenance {
        if self.protocol {
            Provenance::Protocol
        } else {
            Provenance::Published
        }
    }
}

fn run(args: &[String]) -> Result<String, BuildError> {
    let invocation = Invocation::read(args)?;
    match invocation.command.as_deref() {
        Some("new") => {
            let dir = invocation
                .positional
                .first()
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
            let path = build(&invocation.target(), invocation.provenance())?;
            let bytes = std::fs::metadata(&path).map_or(0, |file| file.len());
            Ok(format!("wrote {} ({bytes} bytes)", path.display()))
        }
        Some("check") => {
            let bytes = artifact(&invocation.target(), invocation.provenance())?;
            Ok(format!(
                "admitted ({} bytes, unwritten — `build` writes {})",
                bytes.len(),
                artifact_path(&invocation.target()).display()
            ))
        }
        Some("explain") => {
            let metadata = declaration(&invocation.target())?;
            let rendered = match &invocation.method {
                Some(name) => explain_method(&metadata, name).ok_or_else(|| {
                    BuildError(format!("{name}: the package declares no such method"))
                })?,
                None => explain(&metadata),
            };
            Ok(rendered.trim_end().to_owned())
        }
        _ => Err(BuildError(USAGE.to_owned())),
    }
}
