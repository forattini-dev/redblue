//! Database flush/persistence operations
//!
//! Methods for saving database to disk.

use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};

use crate::storage::layout::{
    FileHeader, SectionEntry, SegmentFlags, SegmentKind, SegmentMetadata, VERSION,
};

use super::Database;

impl Database {
    /// Flush all changes to disk
    pub fn flush(&mut self) -> std::io::Result<()> {
        if !self.dirty {
            return Ok(());
        }

        let segments: Vec<(SegmentKind, Vec<u8>)> = vec![
            (SegmentKind::Ports, self.ports.serialize()),
            (SegmentKind::Subdomains, self.subdomains.serialize()),
            (SegmentKind::Whois, self.whois.serialize()),
            (SegmentKind::Tls, self.tls.serialize()),
            (SegmentKind::Dns, self.dns.serialize()),
            (SegmentKind::Http, self.http.serialize()),
            (SegmentKind::Host, self.hosts.serialize()),
            (SegmentKind::Proxy, self.proxy.serialize()),
            (SegmentKind::Mitre, self.mitre.serialize()),
            (SegmentKind::Ioc, self.iocs.serialize()),
            (SegmentKind::Vuln, self.vulns.serialize()),
            (SegmentKind::Sessions, self.sessions.serialize()),
            (SegmentKind::Playbooks, self.playbooks.serialize()),
            (SegmentKind::Actions, self.actions.serialize()),
            (SegmentKind::Traces, self.traces.serialize()),
            (SegmentKind::Loot, self.loot.serialize()),
        ];

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.path)?;

        // Calculate header start offset based on encryption
        let header_size = if self.encryption.is_some() {
            FileHeader::SIZE + FileHeader::ENCRYPTION_DATA_SIZE
        } else {
            FileHeader::SIZE
        };

        // Reserve space for header (write placeholder)
        let placeholder = FileHeader {
            version: VERSION,
            section_count: segments.len() as u16,
            directory_offset: 0,
            encrypted: self.encryption.is_some(),
        };

        if let Some(ref enc) = self.encryption {
            placeholder.write_encrypted(&mut file, &enc.salt, &enc.key_check)?;
        } else {
            placeholder.write(&mut file)?;
        }

        let mut entries = Vec::new();
        let mut offset = header_size as u64;

        for (seg_idx, (kind, data)) in segments.iter().enumerate() {
            // Encrypt segment if encryption is enabled
            let write_data = if let Some(ref enc) = self.encryption {
                enc.encryptor.encrypt(seg_idx as u32, data)
            } else {
                data.clone()
            };

            file.seek(SeekFrom::Start(offset))?;
            file.write_all(&write_data)?;
            let mut entry = SectionEntry::new(*kind, offset, write_data.len() as u64);
            offset += write_data.len() as u64;

            let metadata_pairs = self.segment_metadata(*kind);
            let metadata_bytes = SegmentMetadata::encode(&metadata_pairs);
            if !metadata_bytes.is_empty() {
                // Encrypt metadata if encryption is enabled
                let write_metadata = if let Some(ref enc) = self.encryption {
                    // Use seg_idx + 1000 to avoid collision with segment page IDs
                    enc.encryptor
                        .encrypt((seg_idx + 1000) as u32, &metadata_bytes)
                } else {
                    metadata_bytes
                };

                file.seek(SeekFrom::Start(offset))?;
                file.write_all(&write_metadata)?;
                entry.metadata_offset = offset;
                entry.metadata_length = write_metadata.len() as u64;
                entry.flags.insert(SegmentFlags::HAS_METADATA);
                offset += write_metadata.len() as u64;
            }

            entries.push(entry);
        }

        let directory_offset = offset;
        let mut dir_buf = Vec::new();
        SectionEntry::write_all(&entries, &mut dir_buf, VERSION);
        file.seek(SeekFrom::Start(directory_offset))?;
        file.write_all(&dir_buf)?;
        file.flush()?;

        let header = FileHeader {
            version: VERSION,
            section_count: entries.len() as u16,
            directory_offset,
            encrypted: self.encryption.is_some(),
        };

        if let Some(ref enc) = self.encryption {
            header.write_encrypted(&mut file, &enc.salt, &enc.key_check)?;
        } else {
            header.write(&mut file)?;
        }
        file.sync_all()?;

        self.dirty = false;
        Ok(())
    }
}
