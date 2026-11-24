# atlas-dc42

Opens DiskCopy 4.2 images (an 84-byte big-endian header, the disk data, optional tag bytes) as a `BlockSource` and computes the format's checksum.

- The header is validated against the file size before the data slice is exposed.
- No `unsafe`. Every length, offset and count read from the disk is checked; damage is an error, not a panic.

## Licence

Licensed under either of Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)) or MIT license
([LICENSE-MIT](LICENSE-MIT)) at your option.
