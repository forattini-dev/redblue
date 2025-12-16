use crate::compression::{GzipDecoder, TarReader};
use std::fs::File;
use std::io::{self, BufReader, Cursor, Read};
use std::path::Path;

pub struct Loader;

impl Loader {
    /// Opens a wordlist file. Handles plain text and .gz files.
    /// For .tar or .tar.gz, use extract_from_archive.
    pub fn open(path: &Path) -> io::Result<Box<dyn Read>> {
        let file = File::open(path)?;

        if let Some(ext) = path.extension() {
            if ext == "gz" || ext == "tgz" {
                // Decompress gzip data into memory and return as Cursor
                let reader = BufReader::new(file);
                let decompressed = GzipDecoder::new(reader)
                    .decompress()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                return Ok(Box::new(Cursor::new(decompressed)));
            }
        }

        Ok(Box::new(BufReader::new(file)))
    }

    /// Extracts a single file from a TAR or TAR.GZ archive.
    /// Returns the content as a String (assuming text).
    /// For huge files, this should be streaming, but `TarReader` doesn't support random access.
    /// We must scan until we find it.
    pub fn extract_from_archive(
        archive_path: &Path,
        filename_inside: &str,
    ) -> io::Result<Option<Box<dyn Read>>> {
        let is_gzipped = archive_path.to_string_lossy().ends_with(".gz")
            || archive_path.to_string_lossy().ends_with(".tgz");

        // Handle decompression - decompress into memory first
        let tar_data: Vec<u8> = if is_gzipped {
            let file = File::open(archive_path)?;
            let reader = BufReader::new(file);
            GzipDecoder::new(reader)
                .decompress()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
        } else {
            let mut file = File::open(archive_path)?;
            let mut data = Vec::new();
            file.read_to_end(&mut data)?;
            data
        };

        let mut tar = TarReader::new(Cursor::new(tar_data));

        loop {
            let entry = tar.next_entry()?;
            match entry {
                Some(e) => {
                    if e.name == filename_inside || e.name.ends_with(filename_inside) {
                        let mut content = vec![0u8; e.size as usize];
                        tar.read_data(e.size, &mut content)?;
                        return Ok(Some(Box::new(Cursor::new(content))));
                    } else {
                        tar.skip_data(e.size)?;
                    }
                }
                None => break,
            }
        }

        Ok(None)
    }
}
