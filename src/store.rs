//! Crash-safe files: a reader sees the old content or the new one, never a torn write.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut file = File::create(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&tmp, path)?;
    File::open(path.parent().expect("files live in a directory"))?.sync_all()
}
