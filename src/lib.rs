// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! DiskCopy 4.2 images: an 84-byte big-endian header, the disk's data,
//! then optional tag bytes (ignored).
//!
//! The data checksum is not verified at open, so a damaged floppy image
//! still opens; [`checksum`] computes it for tools that want to report it.
//!
//! ```no_run
//! use std::path::Path;
//!
//! use atlas_fs_core::io::block::BlockSource;
//!
//! # fn main() -> Result<(), atlas_fs_core::error::Error> {
//! let disk = atlas_dc42::open(Path::new("floppy.dc42"))?;
//! println!("{} bytes of disk", disk.len());
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
// On-disk bytes are hostile. These lints make the usual ways of trusting
// them (unchecked indexing, arithmetic and casts, panicking shortcuts) fail
// the clippy gate. Unit tests and the test fixtures are exempt.
#![warn(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unimplemented,
    clippy::unreachable,
    clippy::unwrap_used
)]
#![cfg_attr(
    any(test, feature = "test-util"),
    allow(
        clippy::arithmetic_side_effects,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::unwrap_used
    )
)]

use std::path::Path;
use std::sync::Arc;

use atlas_fs_core::error::{CorruptKind, Corruption, Error, Location, Result};
use atlas_fs_core::io::block::{BlockSource, Slice};
use atlas_fs_core::io::file::FileSource;

/// Size of the header; the data starts here.
pub const HEADER_LEN: usize = 84;
/// The "private" word at byte 82.
pub const PRIVATE: u16 = 0x0100;
/// Longest disk name in bytes.
pub const MAX_NAME_LEN: usize = 63;
/// The data size is a whole number of these.
const SECTOR: u32 = 512;
/// Bytes read per step by [`checksum`].
const CHUNK: usize = 64 * 1024;
/// The structure name used in errors.
const WHAT: &str = "DiskCopy 4.2 header";

/// The header fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// The disk name bytes (Mac OS Roman), without the length byte.
    pub name: Vec<u8>,
    /// Bytes of disk data after the header.
    pub data_size: u32,
    /// Bytes of tag data after the disk data.
    pub tag_size: u32,
    /// Checksum of the disk data as stored.
    pub data_checksum: u32,
    /// Checksum of the tag data as stored.
    pub tag_checksum: u32,
    /// 0 400K, 1 800K, 2 720K, 3 1440K; other values are kept as read.
    pub disk_format: u8,
    /// The format byte (sides and interleave).
    pub format_byte: u8,
}

fn be32(b: &[u8; HEADER_LEN], at: usize) -> u32 {
    b.get(at..)
        .and_then(<[u8]>::first_chunk::<4>)
        .map_or(0, |w| u32::from_be_bytes(*w))
}

fn corrupt(offset: u64, kind: CorruptKind) -> Error {
    Error::Corrupt(Corruption::new(WHAT, Location::Byte(offset), kind))
}

impl Header {
    /// Parses and validates the header against a file of `file_len` bytes:
    /// the private word, a name of at most 63 bytes, a non-zero data size
    /// that is a multiple of 512, and header, data and tags inside the file.
    pub fn parse(b: &[u8; HEADER_LEN], file_len: u64) -> Result<Self> {
        let private = u16::from_be_bytes([b[82], b[83]]);
        if private != PRIVATE {
            return Err(corrupt(
                82,
                CorruptKind::BadSignature {
                    expected: u64::from(PRIVATE),
                    found: u64::from(private),
                },
            ));
        }
        let name_len = usize::from(b[0]);
        if name_len > MAX_NAME_LEN {
            return Err(corrupt(
                0,
                CorruptKind::OutOfRange {
                    field: "disk name length",
                    value: u64::from(b[0]),
                    limit_name: "longest name",
                    limit: MAX_NAME_LEN as u64,
                },
            ));
        }
        let header = Self {
            name: b.get(1..=name_len).unwrap_or_default().to_vec(),
            data_size: be32(b, 64),
            tag_size: be32(b, 68),
            data_checksum: be32(b, 72),
            tag_checksum: be32(b, 76),
            disk_format: b[80],
            format_byte: b[81],
        };
        if header.data_size == 0 || !header.data_size.is_multiple_of(SECTOR) {
            return Err(corrupt(
                64,
                CorruptKind::InvalidValue {
                    field: "data size",
                    value: u64::from(header.data_size),
                },
            ));
        }
        let end = (HEADER_LEN as u64)
            .checked_add(u64::from(header.data_size))
            .and_then(|n| n.checked_add(u64::from(header.tag_size)))
            .ok_or(corrupt(
                64,
                CorruptKind::Overflow {
                    field: "image size",
                },
            ))?;
        if end > file_len {
            return Err(corrupt(
                64,
                CorruptKind::Truncated {
                    needed: end,
                    available: file_len,
                },
            ));
        }
        Ok(header)
    }
}

/// Reads and validates the header of `file`, and returns it with the disk
/// data as a slice of `file`.
pub fn open_source(file: Arc<dyn BlockSource>) -> Result<(Header, Slice)> {
    let file_len = file.len();
    if file_len < HEADER_LEN as u64 {
        return Err(corrupt(
            0,
            CorruptKind::Truncated {
                needed: HEADER_LEN as u64,
                available: file_len,
            },
        ));
    }
    let mut b = [0u8; HEADER_LEN];
    file.read_at(0, &mut b)?;
    let header = Header::parse(&b, file_len)?;
    let data = Slice::new(file, HEADER_LEN as u64, u64::from(header.data_size))?;
    Ok((header, data))
}

/// Opens the image at `path` read-only; the result is the disk data.
pub fn open(path: &Path) -> Result<Arc<dyn BlockSource>> {
    let file: Arc<dyn BlockSource> = Arc::new(FileSource::open(path)?);
    Ok(Arc::new(open_source(file)?.1))
}

/// The DiskCopy checksum of `len` bytes of `source` from `offset`: each
/// big-endian 16-bit word is added to a 32-bit sum, which is then rotated
/// right by one. `len` must be even, as the header's sizes are; an odd
/// last byte is ignored.
pub fn checksum(source: &dyn BlockSource, offset: u64, len: u64) -> Result<u32> {
    let mut sum: u32 = 0;
    let mut buf = vec![0u8; CHUNK];
    let mut done: u64 = 0;
    // Bounded: each pass advances `done` by at least 2 until it reaches the
    // even part of `len`.
    let even = len & !1;
    while done < even {
        let left = even.saturating_sub(done);
        let n = usize::try_from(left).map_or(CHUNK, |left| left.min(CHUNK));
        let at = offset.checked_add(done).ok_or(Error::OutOfBounds {
            offset,
            len,
            size: source.len(),
        })?;
        let chunk = buf.get_mut(..n).unwrap_or_default();
        source.read_bulk(at, chunk)?;
        for w in chunk.as_chunks::<2>().0 {
            sum = sum
                .wrapping_add(u32::from(u16::from_be_bytes(*w)))
                .rotate_right(1);
        }
        done = done.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
    }
    Ok(sum)
}

#[cfg(any(test, feature = "test-util"))]
#[doc(hidden)]
#[allow(missing_docs)]
pub mod fixtures {
    use super::*;

    /// A DiskCopy 4.2 image: header naming `name`, then `data`, then `tags`.
    /// The checksums are computed.
    pub fn build(name: &[u8], data: &[u8], tags: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; HEADER_LEN];
        out[0] = u8::try_from(name.len()).unwrap();
        out[1..=name.len()].copy_from_slice(name);
        let size = |n: usize| u32::try_from(n).unwrap().to_be_bytes();
        out[64..68].copy_from_slice(&size(data.len()));
        out[68..72].copy_from_slice(&size(tags.len()));
        let sum = |b: &[u8]| {
            checksum(
                &atlas_fs_core::io::block::MemSource::new(b.to_vec()),
                0,
                b.len() as u64,
            )
            .unwrap()
        };
        out[72..76].copy_from_slice(&sum(data).to_be_bytes());
        out[76..80].copy_from_slice(&sum(tags).to_be_bytes());
        out[80] = 1;
        out[81] = 0x22;
        out[82..84].copy_from_slice(&PRIVATE.to_be_bytes());
        out.extend_from_slice(data);
        out.extend_from_slice(tags);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::build;
    use super::*;
    use atlas_fs_core::io::block::MemSource;

    fn src(bytes: Vec<u8>) -> Arc<dyn BlockSource> {
        Arc::new(MemSource::new(bytes))
    }

    fn data(sectors: usize) -> Vec<u8> {
        (0..sectors * 512).map(|i| (i % 251) as u8).collect()
    }

    fn kind(r: Result<(Header, Slice)>) -> CorruptKind {
        match r {
            Err(Error::Corrupt(c)) => c.kind,
            Err(e) => panic!("expected corruption, got {e}"),
            Ok(_) => panic!("expected corruption, got a header"),
        }
    }

    #[test]
    fn opens_and_reads_the_data() {
        let d = data(4);
        let image = build(b"System Tools", &d, &[7u8; 48]);
        let (h, s) = open_source(src(image)).unwrap();
        assert_eq!(h.name, b"System Tools");
        assert_eq!(h.data_size, 2048);
        assert_eq!(h.tag_size, 48);
        assert_eq!(h.disk_format, 1);
        assert_eq!(h.format_byte, 0x22);
        assert_eq!(s.len(), 2048);
        assert_eq!(s.start(), HEADER_LEN as u64);
        let mut buf = vec![0u8; 2048];
        s.read_at(0, &mut buf).unwrap();
        assert_eq!(buf, d);
        // Reads stop at the data: the tags are not part of the disk.
        assert!(s.read_at(2048, &mut [0u8; 1]).is_err());
        // The stored checksum matches the data.
        assert_eq!(checksum(&s, 0, 2048).unwrap(), h.data_checksum);
    }

    #[test]
    fn checksum_known_values() {
        // One word: 0x0102 rotated right by one.
        let s = MemSource::new(vec![0x01, 0x02]);
        assert_eq!(checksum(&s, 0, 2).unwrap(), 0x0102u32.rotate_right(1));
        // Two words, then an odd byte that is ignored.
        let s = MemSource::new(vec![0x00, 0x01, 0x00, 0x01, 0xFF]);
        let want = 1u32.rotate_right(1).wrapping_add(1).rotate_right(1);
        assert_eq!(checksum(&s, 0, 5).unwrap(), want);
        assert_eq!(checksum(&s, 0, 0).unwrap(), 0);
        // Past the end is an error, not a panic.
        assert!(checksum(&s, 4, 4).is_err());
        assert!(checksum(&s, u64::MAX, 4).is_err());
        // Longer than one chunk.
        let s = MemSource::new(vec![0xABu8; CHUNK * 2 + 6]);
        checksum(&s, 0, (CHUNK * 2 + 6) as u64).unwrap();
    }

    #[test]
    fn a_bad_checksum_still_opens() {
        let mut image = build(b"Disk", &data(2), &[]);
        image[72] ^= 0xFF;
        open_source(src(image)).unwrap();
    }

    #[test]
    fn empty_name_is_allowed() {
        let (h, _) = open_source(src(build(b"", &data(1), &[]))).unwrap();
        assert!(h.name.is_empty());
    }

    #[test]
    fn rejects_bad_headers() {
        let good = build(b"Disk", &data(2), &[]);
        let with = |at: usize, bytes: &[u8]| {
            let mut b = good.clone();
            b[at..at + bytes.len()].copy_from_slice(bytes);
            src(b)
        };
        assert!(matches!(
            kind(open_source(with(82, &[0x01, 0x01]))),
            CorruptKind::BadSignature { found: 0x0101, .. }
        ));
        assert!(matches!(
            kind(open_source(with(0, &[64]))),
            CorruptKind::OutOfRange { value: 64, .. }
        ));
        for size in [0u32, 511, 513] {
            assert!(matches!(
                kind(open_source(with(64, &size.to_be_bytes()))),
                CorruptKind::InvalidValue {
                    field: "data size",
                    ..
                }
            ));
        }
        // Data past the end of the file.
        assert!(matches!(
            kind(open_source(with(64, &1536u32.to_be_bytes()))),
            CorruptKind::Truncated { needed: 1620, .. }
        ));
        // Tags past the end of the file.
        assert!(matches!(
            kind(open_source(with(68, &2u32.to_be_bytes()))),
            CorruptKind::Truncated { .. }
        ));
        // The largest sizes: checked arithmetic, no overflow in u64 either.
        let huge = with(64, &[0xFF, 0xFF, 0xFE, 0x00, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert!(matches!(
            kind(open_source(huge)),
            CorruptKind::Truncated { .. }
        ));
        // Shorter than the header.
        assert!(matches!(
            kind(open_source(src(good[..83].to_vec()))),
            CorruptKind::Truncated {
                needed: 84,
                available: 83
            }
        ));
    }

    #[test]
    fn open_reads_a_file_from_disk() {
        let dir = std::env::temp_dir().join(format!("disk-atlas-dc42-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("floppy.image");
        let d = data(3);
        std::fs::write(&path, build(b"Floppy", &d, &[])).unwrap();
        let s = open(&path).unwrap();
        let mut buf = vec![0u8; d.len()];
        s.read_at(0, &mut buf).unwrap();
        assert_eq!(buf, d);
        drop(s);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Writes seed inputs for the `dc42` fuzz target into the directory
    /// named by `ATLAS_FUZZ_SEEDS`, in a `dc42` subfolder. Does nothing
    /// when the variable is unset. Run it with
    /// `cargo test --lib write_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore = "writes files; run by the fuzz CI job"]
    fn write_fuzz_seeds() {
        let Some(root) = std::env::var_os("ATLAS_FUZZ_SEEDS") else {
            return;
        };
        let dir = Path::new(&root).join("dc42");
        std::fs::create_dir_all(&dir).expect("create seed directory");
        std::fs::write(dir.join("valid"), build(b"Seed", &data(4), &[0x5A; 24]))
            .expect("write dc42 seed");
    }
}
