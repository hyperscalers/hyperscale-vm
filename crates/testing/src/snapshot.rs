//! A committed rendering, compared or rewritten.

use std::path::PathBuf;

/// Compare `rendered` with the snapshot committed at
/// `{manifest_dir}/snapshots/{name}.txt`, or rewrite it when the
/// `SNAPSHOT=overwrite` environment variable is set.
///
/// The snapshot is a review artifact rather than an assertion about any
/// particular value: a diff here is the derivation changing, which is a
/// thing to read. A missing file fails with the line that says how to
/// write it, which is the same prompt a moved derivation gets.
///
/// # Panics
///
/// On a missing or unequal snapshot — the test's own verdict.
pub fn snapshot(manifest_dir: &str, name: &str, rendered: &str) {
    let path = PathBuf::from(manifest_dir)
        .join("snapshots")
        .join(format!("{name}.txt"));

    if std::env::var("SNAPSHOT").as_deref() == Ok("overwrite") {
        std::fs::create_dir_all(path.parent().expect("a snapshots directory"))
            .expect("create the snapshots directory");
        std::fs::write(&path, rendered).expect("write the snapshot");
        return;
    }

    let committed = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "{name}: no snapshot at {} ({error}); regenerate with \
             SNAPSHOT=overwrite",
            path.display()
        )
    });
    assert_eq!(
        rendered, committed,
        "{name}: the derivation moved. Read the diff, then regenerate with \
         SNAPSHOT=overwrite if it is the change you meant"
    );
}
