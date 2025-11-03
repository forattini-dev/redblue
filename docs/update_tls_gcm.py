#!/usr/bin/env python3
"""
Update TLS 1.2 implementation to support both GCM and CBC cipher suites
"""

import re

def update_tls_file():
    with open('src/protocols/tls12.rs', 'r') as f:
        content = f.read()

    # Replace the hardcoded cipher suite check in send_encrypted_record
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
            // GCM mode: AEAD encryption
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
            // CBC mode: MAC-then-encrypt
            let mac_key = self
                .client_write_mac
                .ok_or_else(|| "MAC key not available".to_string())?;
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

    with open('src/protocols/tls12.rs', 'w') as f:
        f.write(content)

    print("Updated send_encrypted_record successfully")

if __name__ == '__main__':
    update_tls_file()
