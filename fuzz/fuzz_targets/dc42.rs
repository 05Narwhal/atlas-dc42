// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! Fuzzes the DiskCopy 4.2 reader: the header, the data slice and the
//! checksum.

#![no_main]

use std::sync::Arc;

use atlas_dc42 as dc42;
use atlas_fs_core::io::block::{BlockSource, MemSource};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let file: Arc<dyn BlockSource> = Arc::new(MemSource::new(data));
    let Ok((header, disk)) = dc42::open_source(file) else {
        return;
    };
    // The data lies inside the input, so the checksum and a full read are
    // bounded by the input size.
    let _ = dc42::checksum(&disk, 0, disk.len());
    let mut buf = vec![0u8; usize::try_from(disk.len()).unwrap_or(0)];
    let _ = disk.read_at(0, &mut buf);
    let _ = disk.read_at(disk.len(), &mut [0u8; 1]);
    assert!(header.name.len() <= dc42::MAX_NAME_LEN);
});
