//! Milestone 1 spike, question 4: custom-section round-trip and content
//! addressing.
//!
//! The effect metadata rides a custom section in the component binary (D10).
//! This probe attaches an opaque payload as a custom section to a compiled
//! component, confirms the engine still compiles and runs the modified
//! artifact, extracts the section back without instantiation, and checks that
//! the artifact's identity (its bytes, hence any content address) covers the
//! metadata: same code with different metadata is a different artifact.

use anyhow::{Result, anyhow};
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store};
use wat::parse_str;

const COMPONENT_WAT: &str = r#"
(component
  (core module $m
    (func (export "add") (param i32 i32) (result i32)
      local.get 0
      local.get 1
      i32.add))
  (core instance $i (instantiate $m))
  (func (export "add") (param "a" u32) (param "b" u32) (result u32)
    (canon lift (core func $i "add"))))
"#;

const SECTION_NAME: &str = "hyperscale:effect-metadata";

fn leb128(mut value: u32, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn read_leb128(bytes: &[u8], pos: &mut usize) -> Result<u32> {
    let mut value = 0u32;
    let mut shift = 0;
    loop {
        let byte = *bytes.get(*pos).ok_or_else(|| anyhow!("truncated leb128"))?;
        *pos += 1;
        value |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}

/// Appends a custom section carrying `payload` under [`SECTION_NAME`].
fn attach_metadata(binary: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut content = Vec::new();
    leb128(u32::try_from(SECTION_NAME.len()).unwrap(), &mut content);
    content.extend_from_slice(SECTION_NAME.as_bytes());
    content.extend_from_slice(payload);

    let mut out = binary.to_vec();
    out.push(0); // custom section id
    leb128(u32::try_from(content.len()).unwrap(), &mut out);
    out.extend_from_slice(&content);
    out
}

/// Walks the section framing (shared by core modules and components) and
/// returns the payload of the named custom section. No engine involved.
fn extract_metadata(binary: &[u8]) -> Result<Option<Vec<u8>>> {
    let mut pos = 8; // magic + version preamble
    while pos < binary.len() {
        let id = binary[pos];
        pos += 1;
        let size = read_leb128(binary, &mut pos)? as usize;
        let end = pos + size;
        if id == 0 {
            let mut inner = pos;
            let name_len = read_leb128(binary, &mut inner)? as usize;
            let name = &binary[inner..inner + name_len];
            if name == SECTION_NAME.as_bytes() {
                return Ok(Some(binary[inner + name_len..end].to_vec()));
            }
        }
        pos = end;
    }
    Ok(None)
}

fn runs(engine: &Engine, binary: &[u8]) -> Result<u32> {
    let component = Component::new(engine, binary)?;
    let linker = Linker::<()>::new(engine);
    let mut store = Store::new(engine, ());
    let instance = linker.instantiate(&mut store, &component)?;
    let add = instance.get_typed_func::<(u32, u32), (u32,)>(&mut store, "add")?;
    let (sum,) = add.call(&mut store, (2, 3))?;
    add.post_return(&mut store)?;
    Ok(sum)
}

#[test]
fn metadata_section_round_trips_and_addresses_the_artifact() -> Result<()> {
    let engine = Engine::new(&Config::new())?;
    let plain = parse_str(COMPONENT_WAT)?;
    assert_eq!(extract_metadata(&plain)?, None);

    let payload = b"opaque effect metadata bytes \x00\xff";
    let tagged = attach_metadata(&plain, payload);

    // The engine accepts and runs the modified artifact identically.
    assert_eq!(runs(&engine, &plain)?, 5);
    assert_eq!(runs(&engine, &tagged)?, 5);

    // Extraction is engine-free and exact.
    assert_eq!(extract_metadata(&tagged)?.as_deref(), Some(&payload[..]));

    // The artifact's bytes — hence any content address — cover the metadata.
    let other = attach_metadata(&plain, b"different metadata");
    assert_ne!(tagged, other);
    assert_ne!(tagged, plain);
    Ok(())
}
