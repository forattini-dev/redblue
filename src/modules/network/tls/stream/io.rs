//! TLS stream I/O implementations
//!
//! Provides Read and Write trait implementations for TlsStream,
//! enabling transparent encrypted I/O over TLS connections.

use super::super::types::ContentType;
use super::TlsStream;

use std::io::{Read, Write};
use std::net::TcpStream;

impl TlsStream {
    /// Read raw TLS record from underlying stream
    ///
    /// Returns: (content_type, version, payload)
    pub(super) fn read_tls_record_internal(
        &mut self,
    ) -> std::io::Result<(ContentType, (u8, u8), Vec<u8>)> {
        let mut header = [0u8; 5];
        self.stream.read_exact(&mut header)?;

        let content_type = ContentType::from_u8(header[0]).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Unknown TLS content type {}", header[0]),
            )
        })?;

        let version = (header[1], header[2]);
        let length = ((header[3] as usize) << 8) | (header[4] as usize);

        let mut payload = vec![0u8; length];
        self.stream.read_exact(&mut payload)?;

        Ok((content_type, version, payload))
    }

    /// Receive TLS record with optional decryption
    ///
    /// Handles server encryption state and decrypts if needed.
    pub(super) fn receive_tls_record(&mut self) -> Result<(ContentType, Vec<u8>), String> {
        let (content_type, _version, payload) = self
            .read_tls_record_internal()
            .map_err(|e| format!("Failed to read TLS record: {}", e))?;

        if self.server_encryption_active
            && matches!(
                content_type,
                ContentType::Handshake | ContentType::ApplicationData
            )
        {
            let plaintext = self.decrypt_record_payload(content_type, &payload)?;
            Ok((content_type, plaintext))
        } else {
            Ok((content_type, payload))
        }
    }

    /// Get inner TCP stream for bidirectional copying
    ///
    /// Consumes the TlsStream and returns the underlying TcpStream.
    /// Useful for protocol upgrades or raw socket access after TLS.
    pub fn into_inner(self) -> TcpStream {
        self.stream
    }
}

impl Read for TlsStream {
    /// Read decrypted application data
    ///
    /// This implements buffered reading of TLS application data:
    /// 1. If buffered data exists, return it first
    /// 2. Otherwise read new TLS records until ApplicationData arrives
    /// 3. Handle alerts, handshake messages, and ChangeCipherSpec internally
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.handshake_complete {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "TLS handshake not complete",
            ));
        }

        // If we have buffered data, return it first
        if self.buffer_pos < self.read_buffer.len() {
            let remaining = self.read_buffer.len() - self.buffer_pos;
            let to_copy = buf.len().min(remaining);
            buf[..to_copy]
                .copy_from_slice(&self.read_buffer[self.buffer_pos..self.buffer_pos + to_copy]);
            self.buffer_pos += to_copy;

            // Clear buffer if fully consumed
            if self.buffer_pos >= self.read_buffer.len() {
                self.read_buffer.clear();
                self.buffer_pos = 0;
            }

            return Ok(to_copy);
        }

        if buf.is_empty() {
            return Ok(0);
        }

        // Read TLS records until we get application data
        loop {
            let (content_type, _version, payload) = match self.read_tls_record_internal() {
                Ok(record) => record,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(0),
                Err(e) => return Err(e),
            };

            let data = if self.server_encryption_active
                && matches!(
                    content_type,
                    ContentType::Handshake | ContentType::ApplicationData
                ) {
                self.decrypt_record_payload(content_type, &payload)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
            } else {
                payload
            };

            match content_type {
                ContentType::ApplicationData => {
                    if data.is_empty() {
                        continue;
                    }

                    let to_copy = buf.len().min(data.len());
                    buf[..to_copy].copy_from_slice(&data[..to_copy]);

                    // Buffer any remaining data
                    if data.len() > to_copy {
                        self.read_buffer = data[to_copy..].to_vec();
                        self.buffer_pos = 0;
                    }

                    return Ok(to_copy);
                }
                ContentType::Handshake => {
                    // Post-handshake messages (e.g., NewSessionTicket in TLS 1.3)
                    if !data.is_empty() {
                        self.handshake_messages.extend_from_slice(&data);
                    }
                    continue;
                }
                ContentType::ChangeCipherSpec => {
                    // TLS 1.3 compatibility mode or TLS 1.2 cipher change
                    self.server_encryption_active = true;
                    self.server_sequence = 0;
                    continue;
                }
                ContentType::Alert => {
                    if data.len() >= 2 {
                        let level = data[0];
                        let description = data[1];
                        let kind = if level == 2 {
                            std::io::ErrorKind::ConnectionAborted
                        } else {
                            std::io::ErrorKind::Other
                        };
                        return Err(std::io::Error::new(
                            kind,
                            format!(
                                "TLS alert received: level={}, description={}",
                                level, description
                            ),
                        ));
                    }
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "TLS alert received",
                    ));
                }
            }
        }
    }
}

impl Write for TlsStream {
    /// Write encrypted application data
    ///
    /// Fragments data into TLS records of maximum 16384 bytes (2^14)
    /// per RFC 5246 section 6.2.1, then encrypts and sends each record.
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if !self.handshake_complete {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "TLS handshake not complete",
            ));
        }

        if buf.is_empty() {
            return Ok(0);
        }

        if !self.client_encryption_active {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "TLS cipher not activated",
            ));
        }

        // Maximum TLS record fragment size per RFC 5246
        const MAX_FRAGMENT: usize = 16_384; // 2^14

        let mut offset = 0;
        while offset < buf.len() {
            let end = (offset + MAX_FRAGMENT).min(buf.len());
            let chunk = &buf[offset..end];
            self.send_record(ContentType::ApplicationData, chunk, true)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            offset = end;
        }

        Ok(buf.len())
    }

    /// Flush the underlying TCP stream
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}
