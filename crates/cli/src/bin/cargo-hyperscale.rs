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

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;

use hyperscale_vm_cli::{
    Address, BuildError, NetworkId, PrincipalAddr, Provenance, Value, artifact, artifact_path,
    build, declaration, explain, explain_issued, explain_method, publish_envelope, scaffold,
};

const USAGE: &str = "\
cargo hyperscale — build a package crate into an artifact the chain admits

    cargo hyperscale new <path>      scaffold a package crate; --member joins
                                     the enclosing guests workspace instead of
                                     standing alone
    cargo hyperscale build [dir]     build, attach, and admit; writes the artifact.
                                     With `--envelope <out> --payer <addr>
                                     --network <id>`, also writes the unsigned
                                     publish intent a host with keys signs and
                                     submits
    cargo hyperscale check [dir]     the same verdict, without the write
    cargo hyperscale explain [dir]   print what the package declares

`dir` defaults to the current directory. Pass `--protocol` to build under
the gate genesis seeds a package through, which is the only one that
admits a claim to totality. Pass `--method <name>` to `explain` to print
one method rather than the whole package, or `--resources` to print what
every resource it issues says to a holder — with `--config <field>=<addr>`
for each configuration field those rules read, and `--instance <addr>` for
the component they were sealed into.
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
    member: bool,
    method: Option<String>,
    resources: bool,
    /// Where the unsigned publish intent goes, when the build writes one.
    envelope: Option<PathBuf>,
    /// Who the intent names as its fee payer.
    payer: Option<Address>,
    /// Which network the intent is for.
    network: Option<u8>,
    /// The configuration a resource's rules seal against, by field name.
    config: BTreeMap<String, Value>,
    instance: Option<Address>,
}

/// One address as an author writes it: the human-readable form, whose
/// leading word the decoder checks against the tag byte.
///
/// The network half is the text's own and is not checked here — a
/// package's declaration is the same on every network, and what this
/// reads is which address, not which chain.
fn read_address(text: &str) -> Result<Address, BuildError> {
    Address::from_text(text)
        .map(|(address, _)| address)
        .map_err(|error| BuildError(format!("{text}: {error}")))
}

/// One configuration value as an author writes it: a tagged address, a
/// decimal integer — `u64` where it fits, or suffixed `u64`/`u128` to
/// say so — or `0x…` bytes. A `Value` carries its own kind, so the
/// spelling is the type, and the sealed record's field is compared at
/// the kind the author spelled.
fn read_value(text: &str) -> Result<Value, BuildError> {
    if let Some(hex) = text.strip_prefix("0x") {
        if hex.len() % 2 != 0 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(BuildError(format!("{text}: `0x…` takes whole hex bytes")));
        }
        let bytes = (0..hex.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).expect("checked hex"))
            .collect();
        return Ok(Value::Bytes(bytes));
    }
    if let Some(digits) = text.strip_suffix("u64") {
        return digits
            .parse()
            .map(Value::U64)
            .map_err(|error| BuildError(format!("{text}: {error}")));
    }
    if let Some(digits) = text.strip_suffix("u128") {
        return digits
            .parse()
            .map(Value::U128)
            .map_err(|error| BuildError(format!("{text}: {error}")));
    }
    if text.chars().all(|c| c.is_ascii_digit()) && !text.is_empty() {
        if let Ok(number) = text.parse() {
            return Ok(Value::U64(number));
        }
        return text
            .parse()
            .map(Value::U128)
            .map_err(|error| BuildError(format!("{text}: {error}")));
    }
    read_address(text).map(Value::Address).map_err(|_| {
        BuildError(format!(
            "{text}: a configuration value is a tagged address, a decimal integer \
             (suffix `u64`/`u128` to fix the width), or `0x…` bytes"
        ))
    })
}

impl Invocation {
    /// Read `args`, refusing a flag whose value is missing.
    fn read(args: &[String]) -> Result<Self, BuildError> {
        let mut invocation = Self {
            command: args.first().cloned(),
            positional: Vec::new(),
            protocol: false,
            member: false,
            method: None,
            resources: false,
            envelope: None,
            payer: None,
            network: None,
            config: BTreeMap::new(),
            instance: None,
        };
        let mut rest = args.iter().skip(1);
        while let Some(arg) = rest.next() {
            match arg.as_str() {
                "--protocol" => invocation.protocol = true,
                "--member" => invocation.member = true,
                "--resources" => invocation.resources = true,
                "--config" => {
                    let pair = rest
                        .next()
                        .ok_or_else(|| BuildError("`--config` takes `<field>=<value>`".into()))?;
                    let (field, address) = pair.split_once('=').ok_or_else(|| {
                        BuildError(format!("{pair}: `--config` takes `<field>=<value>`"))
                    })?;
                    invocation
                        .config
                        .insert(field.to_owned(), read_value(address)?);
                }
                "--envelope" => {
                    let out = rest
                        .next()
                        .ok_or_else(|| BuildError("`--envelope` takes an output path".into()))?;
                    invocation.envelope = Some(PathBuf::from(out));
                }
                "--payer" => {
                    let text = rest
                        .next()
                        .ok_or_else(|| BuildError("`--payer` takes an address".into()))?;
                    invocation.payer = Some(read_address(text)?);
                }
                "--network" => {
                    let text = rest
                        .next()
                        .ok_or_else(|| BuildError("`--network` takes a network id".into()))?;
                    invocation.network = Some(
                        text.parse()
                            .map_err(|error| BuildError(format!("{text}: {error}")))?,
                    );
                }
                "--instance" => {
                    let text = rest
                        .next()
                        .ok_or_else(|| BuildError("`--instance` takes an address".into()))?;
                    invocation.instance = Some(read_address(text)?);
                }
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
            if invocation.member {
                scaffold::member(&dir)?;
            } else {
                scaffold::package(&dir)?;
            }
            Ok(format!(
                "scaffolded {}\n    cargo hyperscale check {}",
                dir.display(),
                dir.display()
            ))
        }
        Some("build") => {
            let path = build(&invocation.target(), invocation.provenance())?;
            let bytes = std::fs::metadata(&path).map_or(0, |file| file.len());
            let Some(out) = &invocation.envelope else {
                return Ok(format!("wrote {} ({bytes} bytes)", path.display()));
            };
            let (Some(payer), Some(network)) = (invocation.payer, invocation.network) else {
                return Err(BuildError(
                    "`--envelope` names a fee payer and a network: pass `--payer <addr>`                      and `--network <id>`"
                        .into(),
                ));
            };
            let payer = PrincipalAddr::try_from(payer)
                .map_err(|_| BuildError("`--payer` takes a principal's address".into()))?;
            let artifact_bytes = std::fs::read(&path)
                .map_err(|error| BuildError(format!("read {}: {error}", path.display())))?;
            let intent = publish_envelope(artifact_bytes, payer, NetworkId(network))?;
            std::fs::write(out, &intent)
                .map_err(|error| BuildError(format!("write {}: {error}", out.display())))?;
            Ok(format!(
                "wrote {} ({bytes} bytes)\nwrote {} — the unsigned publish intent; a host                  with keys states its terms, signs, and submits it",
                path.display(),
                out.display()
            ))
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
            let rendered = match (&invocation.method, invocation.resources) {
                (Some(_), true) => {
                    return Err(BuildError(
                        "`--method` and `--resources` ask different questions; pass one".into(),
                    ));
                }
                (Some(name), false) => explain_method(&metadata, name).ok_or_else(|| {
                    BuildError(format!("{name}: the package declares no such method"))
                })?,
                (None, true) => explain_issued(&metadata, invocation.instance, &invocation.config)?,
                (None, false) => explain(&metadata),
            };
            Ok(rendered.trim_end().to_owned())
        }
        _ => Err(BuildError(USAGE.to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use super::{Value, read_value};

    /// The spelling is the type: a bare integer is the narrow width, a
    /// suffix fixes it, hex is bytes, and anything else must be an
    /// address — refused naming the admissible spellings.
    #[test]
    fn a_configuration_value_parses_by_its_spelling() {
        assert_eq!(read_value("7").unwrap(), Value::U64(7));
        assert_eq!(read_value("7u128").unwrap(), Value::U128(7));
        assert_eq!(
            read_value("340282366920938463463374607431768211455").unwrap(),
            Value::U128(u128::MAX)
        );
        assert_eq!(
            read_value("0x0a0b").unwrap(),
            Value::Bytes(vec![0x0A, 0x0B])
        );
        let refused = read_value("sideways").expect_err("no spelling admits it");
        assert!(refused.to_string().contains("tagged address"), "{refused}");
        assert!(refused.to_string().contains("`0x…` bytes"), "{refused}");
    }
}
