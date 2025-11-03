#!/usr/bin/env python3
"""
Final atomic application of TLS GCM support
Reads the file, makes ALL changes at once, writes back, and triggers build
"""

import re
import subprocess
import sys

def main():
    filepath = 'src/protocols/tls12.rs'

    # Read entire file
    with open(filepath, 'r') as f:
        content = f.read()

    # 1. Ensure GCM import exists
    if 'use super::gcm' not in content:
        content = content.replace(
            'use super::crypto::\n    aes128_cbc_decrypt, aes128_cbc_encrypt, hmac_sha256, sha256, tls12_prf, SecureRandom,\n};',
            'use super::crypto::\n    aes128_cbc_decrypt, aes128_cbc_encrypt, hmac_sha256, sha256, tls12_prf, SecureRandom,\n};\nuse super::gcm::{aes128_gcm_decrypt, aes128_gcm_encrypt};'
        )

    # 2. Replace single cipher suite with multiple
    content = re.sub(
        r'const TLS_RSA_WITH_AES_128_CBC_SHA256: u16 = 0x003C;\nconst SUPPORTED_CIPHER_SUITES: &\[u16\] = &\[TLS_RSA_WITH_AES_128_CBC_SHA256\];',
        '''const TLS_RSA_WITH_AES_128_GCM_SHA256: u16 = 0x009C;
const TLS_RSA_WITH_AES_256_GCM_SHA384: u16 = 0x009D;
const TLS_RSA_WITH_AES_128_CBC_SHA256: u16 = 0x003C;
const TLS_RSA_WITH_AES_256_CBC_SHA256: u16 = 0x003D;
const SUPPORTED_CIPHER_SUITES: &[u16] = &[TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_GCM_SHA384, TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_RSA_WITH_AES_256_CBC_SHA256];

fn is_gcm_cipher(cipher_suite: u16) -> bool { matches!(cipher_suite, TLS_RSA_WITH_AES_128_GCM_SHA256 | TLS_RSA_WITH_AES_256_GCM_SHA384) }
fn is_cbc_cipher(cipher_suite: u16) -> bool { matches!(cipher_suite, TLS_RSA_WITH_AES_128_CBC_SHA256 | TLS_RSA_WITH_AES_256_CBC_SHA256) }''',
        content
    )

    # 3. Fix send_encrypted_record - find and replace the hardcoded check
    old_send = r'''        if cipher_suite != TLS_RSA_WITH_AES_128_CBC_SHA256 \{
            return Err\(format!\(
                "Unsupported cipher suite: 0x\{:04X\}",
                cipher_suite
            \)\);
        \}

        let mac_key = self
            \.client_write_mac
            \.ok_or_else\(\|\| "MAC key not available"\.to_string\(\)\)\?;

        let mut mac_input = Vec::with_capacity\(13 \+ data\.len\(\)\);
        mac_input\.extend_from_slice\(&self\.client_seq\.to_be_bytes\(\)\);
        mac_input\.push\(content_type\);
        mac_input\.push\(TLS_VERSION_MAJOR\);
        mac_input\.push\(TLS_VERSION_MINOR\);
        mac_input\.extend_from_slice\(&\(data\.len\(\) as u16\)\.to_be_bytes\(\)\);
        mac_input\.extend_from_slice\(data\);

        let mac = hmac_sha256\(&mac_key, &mac_input\);

        let mut plaintext = Vec::with_capacity\(data\.len\(\) \+ mac\.len\(\)\);
        plaintext\.extend_from_slice\(data\);
        plaintext\.extend_from_slice\(&mac\);

        let ciphertext = aes128_cbc_encrypt\(&key, &iv, &plaintext\);'''

    new_send = '''        let ciphertext = if is_gcm_cipher(cipher_suite) {
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&iv[..12]);
            let mut aad = Vec::with_capacity(13);
            aad.extend_from_slice(&self.client_seq.to_be_bytes());
            aad.push(content_type);
            aad.push(TLS_VERSION_MAJOR);
            aad.push(TLS_VERSION_MINOR);
            aad.extend_from_slice(&(data.len() as u16).to_be_bytes());
            aes128_gcm_encrypt(&key, &nonce, data, &aad)
        } else if is_cbc_cipher(cipher_suite) {
            let mac_key = self.client_write_mac.ok_or_else(|| "MAC key not available".to_string())?;
            let mut mac_input = Vec::with_capacity(13 + data.len());
            mac_input.extend_from_slice(&self.client_seq.to_be_bytes());
            mac_input.push(content_type);
            mac_input.push(TLS_VERSION_MAJOR);
            mac_input.push(TLS_VERSION_MINOR);
            mac_input.extend_from_slice(&(data.len() as u16).to_be_bytes());
            mac_input.extend_from_slice(data);
            let mac = hmac_sha256(&mac_key, &mac_input);
            let mut plaintext = Vec::with_capacity(data.len() + mac.len());
            plaintext.extend_from_slice(data);
            plaintext.extend_from_slice(&mac);
            aes128_cbc_encrypt(&key, &iv, &plaintext)
        } else {
            return Err(format!("Unsupported cipher suite: 0x{:04X}", cipher_suite));
        };'''

    content = re.sub(old_send, new_send, content)

    # 4. Fix receive_encrypted_record
    old_recv = r'''        if cipher_suite != TLS_RSA_WITH_AES_128_CBC_SHA256 \{
            return Err\(RecordReadError::Io\(io::Error::new\(
                io::ErrorKind::InvalidData,
                format!\("Unsupported cipher suite: 0x\{:04X\}", cipher_suite\),
            \)\)\);
        \}

        let mac_key = self
            \.server_write_mac
            \.ok_or_else\(\|\| RecordReadError::ConnectionClosed\)\?;

        let plaintext = match aes128_cbc_decrypt\(&key, &iv, &ciphertext\) \{
            Ok\(data\) => data,
            Err\(err\) => \{
                return Err\(RecordReadError::Io\(io::Error::new\(
                    io::ErrorKind::InvalidData,
                    err,
                \)\)\)
            \}
        \};

        if plaintext\.len\(\) < 32 \{
            return Err\(RecordReadError::Io\(io::Error::new\(
                io::ErrorKind::InvalidData,
                "TLS record shorter than MAC",
            \)\)\);
        \}

        let data_len = plaintext\.len\(\) - 32;
        let \(data, received_mac\) = plaintext\.split_at\(data_len\);

        let mut mac_input = Vec::with_capacity\(13 \+ data\.len\(\)\);
        mac_input\.extend_from_slice\(&self\.server_seq\.to_be_bytes\(\)\);
        mac_input\.push\(expected_content_type\);
        mac_input\.push\(TLS_VERSION_MAJOR\);
        mac_input\.push\(TLS_VERSION_MINOR\);
        mac_input\.extend_from_slice\(&\(data\.len\(\) as u16\)\.to_be_bytes\(\)\);
        mac_input\.extend_from_slice\(data\);

        let expected_mac = hmac_sha256\(&mac_key, &mac_input\);
        if expected_mac\.as_slice\(\) != received_mac \{
            return Err\(RecordReadError::Io\(io::Error::new\(
                io::ErrorKind::InvalidData,
                "TLS record MAC verification failed",
            \)\)\);
        \}

        self\.server_seq = self\.server_seq\.wrapping_add\(1\);
        Ok\(data\.to_vec\(\)\)'''

    new_recv = '''        let data = if is_gcm_cipher(cipher_suite) {
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&iv[..12]);
            let mut aad = Vec::with_capacity(13);
            aad.extend_from_slice(&self.server_seq.to_be_bytes());
            aad.push(expected_content_type);
            aad.push(TLS_VERSION_MAJOR);
            aad.push(TLS_VERSION_MINOR);
            let plaintext_len = ciphertext.len().saturating_sub(16);
            aad.extend_from_slice(&(plaintext_len as u16).to_be_bytes());
            match aes128_gcm_decrypt(&key, &nonce, &ciphertext, &aad) {
                Ok(data) => data,
                Err(err) => return Err(RecordReadError::Io(io::Error::new(io::ErrorKind::InvalidData, err)))
            }
        } else if is_cbc_cipher(cipher_suite) {
            let mac_key = self.server_write_mac.ok_or_else(|| RecordReadError::ConnectionClosed)?;
            let plaintext = match aes128_cbc_decrypt(&key, &iv, &ciphertext) {
                Ok(data) => data,
                Err(err) => return Err(RecordReadError::Io(io::Error::new(io::ErrorKind::InvalidData, err)))
            };
            if plaintext.len() < 32 {
                return Err(RecordReadError::Io(io::Error::new(io::ErrorKind::InvalidData, "TLS record shorter than MAC")));
            }
            let data_len = plaintext.len() - 32;
            let (data, received_mac) = plaintext.split_at(data_len);
            let mut mac_input = Vec::with_capacity(13 + data.len());
            mac_input.extend_from_slice(&self.server_seq.to_be_bytes());
            mac_input.push(expected_content_type);
            mac_input.push(TLS_VERSION_MAJOR);
            mac_input.push(TLS_VERSION_MINOR);
            mac_input.extend_from_slice(&(data.len() as u16).to_be_bytes());
            mac_input.extend_from_slice(data);
            let expected_mac = hmac_sha256(&mac_key, &mac_input);
            if expected_mac.as_slice() != received_mac {
                return Err(RecordReadError::Io(io::Error::new(io::ErrorKind::InvalidData, "TLS record MAC verification failed")));
            }
            data.to_vec()
        } else {
            return Err(RecordReadError::Io(io::Error::new(io::ErrorKind::InvalidData, format!("Unsupported cipher suite: 0x{:04X}", cipher_suite))));
        };

        self.server_seq = self.server_seq.wrapping_add(1);
        Ok(data)'''

    content = re.sub(old_recv, new_recv, content)

    # Write back atomically
    with open(filepath, 'w') as f:
        f.write(content)

    print("✅ Applied all TLS GCM changes")

    # Immediately trigger build to lock changes
    print("🔨 Building to lock changes...")
    result = subprocess.run(['cargo', 'build', '--release'], capture_output=True, text=True)

    if result.returncode == 0:
        print("✅ Build successful! Changes locked.")
        return 0
    else:
        print("❌ Build failed:")
        print(result.stderr[-500:] if len(result.stderr) > 500 else result.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())
