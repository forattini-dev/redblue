# Next Steps: Implementing Server Initial Parser

## 📊 Current Status

✅ **QUIC Initial Packet: WORKING**
- Quinn server accepts our packets (proven by server logs)
- All cryptographic components validated (AEAD, HP, HKDF)
- Packet structure is RFC-compliant

⚠️ **Issue:** Client `recv_from()` not receiving server response (EAGAIN timeout)

🎯 **Next Phase:** Implement Server Initial parser (independent of networking issue)

## 🔍 Quinn Code Study

### Key Files Analyzed
- `/docs/quinn/quinn-proto/src/packet.rs` - Packet encoding/decoding
- `/docs/quinn/quinn-proto/src/connection.rs` - Connection state machine

### Quinn's Decoding Flow

```rust
// 1. Decode protected header (before HP removal)
ProtectedHeader::decode(buf, cid_parser, supported_versions, grease_quic_bit)

// 2. Extract packet type
match protected_header {
    ProtectedHeader::Initial(initial_header) => {
        // Server Initial packet
    }
    _ => // Other packet types
}

// 3. Remove header protection
packet.decrypt_header(&header_crypto)

// 4. Decrypt payload
packet.decrypt_body(&payload_crypto, packet_number)

// 5. Parse frames
while has_data {
    match Frame::decode(buf) {
        Frame::Crypto(crypto_frame) => {
            // Contains TLS ServerHello
        }
        _ => // Other frames
    }
}
```

### Server Initial Packet Structure (from Quinn)

```
Long Header:
├─ First byte: 0xc0-0xcf (Initial type + PN length, protected)
├─ Version: 4 bytes (0x00000001)
├─ DCID length: 1 byte
├─ DCID: variable (our SCID becomes server's DCID)
├─ SCID length: 1 byte
├─ SCID: variable (server's new connection ID)
├─ Token length: varint (0 for server Initial)
├─ Length: varint (remaining packet length including PN + payload + tag)
├─ Packet Number: 1-4 bytes (protected)
└─ Encrypted Payload:
    ├─ CRYPTO frames (containing TLS messages)
    ├─ ACK frames (acknowledging our Initial)
    ├─ PADDING frames
    └─ Auth Tag: 16 bytes (AES-128-GCM tag)
```

## 🛠️ Implementation Plan

### Phase 1: Server Initial Decoder

**File:** `src/protocols/quic/packet.rs`

```rust
/// Decode a Server Initial packet (still encrypted)
pub fn decode_server_initial(data: &[u8]) -> Result<ServerInitialPacket, String> {
    let mut cursor = 0;

    // 1. Parse long header (same as client Initial)
    let first_byte = data[cursor]; cursor += 1;
    if (first_byte & 0x80) == 0 {
        return Err("Not a long header".to_string());
    }

    let version = u32::from_be_bytes([
        data[cursor], data[cursor+1], data[cursor+2], data[cursor+3]
    ]);
    cursor += 4;

    // 2. Parse connection IDs
    let dcid_len = data[cursor] as usize; cursor += 1;
    let dcid = &data[cursor..cursor+dcid_len]; cursor += dcid_len;

    let scid_len = data[cursor] as usize; cursor += 1;
    let scid = &data[cursor..cursor+scid_len]; cursor += scid_len;

    // 3. Parse token (should be empty for server Initial)
    let token_len = decode_varint(&data[cursor..])?; cursor += varint_len(token_len);
    cursor += token_len as usize; // Skip token if present

    // 4. Parse payload length
    let payload_len = decode_varint(&data[cursor..])?; cursor += varint_len(payload_len);

    // 5. Packet number is still protected at this point
    let header_end = cursor;
    let pn_offset = cursor;

    Ok(ServerInitialPacket {
        first_byte,
        version,
        dcid: dcid.to_vec(),
        scid: scid.to_vec(),
        payload_len,
        pn_offset,
        data: data.to_vec(),
    })
}
```

### Phase 2: Header Protection Removal

**File:** `src/protocols/quic/crypto.rs`

```rust
/// Remove header protection from server packet
pub fn remove_header_protection(
    packet: &mut [u8],
    pn_offset: usize,
    hp_key: &[u8; 16],
) -> Result<(u8, u64), String> {
    // 1. Extract sample (16 bytes starting at PN + 4)
    let sample_offset = pn_offset + 4;
    let sample = &packet[sample_offset..sample_offset + 16];

    // 2. Generate mask using AES-ECB
    let mask = aes_ecb_encrypt(sample, hp_key)?;

    // 3. Unmask first byte (long header: XOR with mask[0] & 0x0f)
    packet[0] ^= mask[0] & 0x0f;

    // 4. Extract PN length from unmasked first byte
    let pn_len = ((packet[0] & 0x03) + 1) as usize;

    // 5. Unmask packet number bytes
    for i in 0..pn_len {
        packet[pn_offset + i] ^= mask[1 + i];
    }

    // 6. Decode packet number
    let pn = match pn_len {
        1 => packet[pn_offset] as u64,
        2 => u16::from_be_bytes([packet[pn_offset], packet[pn_offset+1]]) as u64,
        3 => u32::from_be_bytes([0, packet[pn_offset], packet[pn_offset+1], packet[pn_offset+2]]) as u64,
        4 => u32::from_be_bytes([
            packet[pn_offset], packet[pn_offset+1],
            packet[pn_offset+2], packet[pn_offset+3]
        ]) as u64,
        _ => return Err("Invalid PN length".to_string()),
    };

    Ok((pn_len as u8, pn))
}
```

### Phase 3: AEAD Decryption

**File:** `src/protocols/quic/crypto.rs`

```rust
/// Decrypt server Initial payload
pub fn decrypt_server_initial(
    packet: &[u8],
    pn_offset: usize,
    pn_len: usize,
    pn: u64,
    server_key: &[u8; 16],
    server_iv: &[u8; 12],
) -> Result<Vec<u8>, String> {
    // 1. AAD = header (from first byte to end of PN)
    let aad = &packet[0..pn_offset + pn_len];

    // 2. Ciphertext = payload + tag (16 bytes)
    let payload_start = pn_offset + pn_len;
    let ciphertext = &packet[payload_start..];

    // 3. Build nonce (IV XOR packet number)
    let mut nonce = *server_iv;
    for i in 0..8 {
        nonce[12 - 8 + i] ^= ((pn >> (56 - i * 8)) & 0xff) as u8;
    }

    // 4. Decrypt with AES-128-GCM
    aes_128_gcm_decrypt(ciphertext, &nonce, aad, server_key)
}
```

### Phase 4: CRYPTO Frame Parsing

**File:** `src/protocols/quic/frame.rs`

```rust
/// Parse CRYPTO frame from decrypted payload
pub fn parse_crypto_frame(data: &[u8]) -> Result<CryptoFrame, String> {
    let mut cursor = 0;

    // 1. Frame type (0x06 for CRYPTO)
    let frame_type = decode_varint(&data[cursor..])?; cursor += varint_len(frame_type);
    if frame_type != 0x06 {
        return Err(format!("Expected CRYPTO frame (0x06), got 0x{:02x}", frame_type));
    }

    // 2. Offset (usually 0 for first fragment)
    let offset = decode_varint(&data[cursor..])?; cursor += varint_len(offset);

    // 3. Length
    let length = decode_varint(&data[cursor..])?; cursor += varint_len(length);

    // 4. Data (TLS handshake message)
    let tls_data = &data[cursor..cursor + length as usize];

    Ok(CryptoFrame {
        offset,
        data: tls_data.to_vec(),
    })
}
```

### Phase 5: TLS ServerHello Parsing

**File:** `src/protocols/tls13.rs`

```rust
/// Parse TLS ServerHello from CRYPTO frame data
pub fn parse_server_hello(data: &[u8]) -> Result<ServerHello, String> {
    let mut cursor = 0;

    // 1. Handshake type (0x02 for ServerHello)
    if data[cursor] != 0x02 {
        return Err(format!("Expected ServerHello (0x02), got 0x{:02x}", data[cursor]));
    }
    cursor += 1;

    // 2. Length (3 bytes, big-endian)
    let msg_len = u32::from_be_bytes([0, data[cursor], data[cursor+1], data[cursor+2]]) as usize;
    cursor += 3;

    // 3. TLS version (0x0303 for compatibility)
    cursor += 2;

    // 4. Server random (32 bytes)
    let server_random = &data[cursor..cursor+32]; cursor += 32;

    // 5. Session ID (1 byte length + data, should be 0 for TLS 1.3)
    let session_id_len = data[cursor] as usize; cursor += 1 + session_id_len;

    // 6. Cipher suite (2 bytes)
    let cipher_suite = u16::from_be_bytes([data[cursor], data[cursor+1]]); cursor += 2;

    // 7. Compression method (1 byte, should be 0x00)
    cursor += 1;

    // 8. Extensions length
    let ext_len = u16::from_be_bytes([data[cursor], data[cursor+1]]) as usize; cursor += 2;

    // 9. Parse extensions (key_share, supported_versions, etc.)
    let extensions = parse_extensions(&data[cursor..cursor+ext_len])?;

    Ok(ServerHello {
        random: server_random.try_into().unwrap(),
        cipher_suite,
        extensions,
    })
}
```

## 🔬 Testing Strategy

### 1. Unit Tests with Known Data
```rust
#[test]
fn test_decode_server_initial() {
    // Use captured packet from Quinn server
    let packet_hex = "c000..."; // Hex dump from tcpdump
    let packet_data = hex::decode(packet_hex).unwrap();

    let result = decode_server_initial(&packet_data);
    assert!(result.is_ok());
}
```

### 2. Integration Test with Quinn Client
Study how Quinn client processes Server Initial:
- `/docs/quinn/quinn/examples/client.rs`
- Look for packet reception and decryption flow

### 3. Live Testing
Once parser is ready, fix networking issue and test with real Quinn server.

## 📚 References

### Quinn Source Code
- `quinn-proto/src/packet.rs` - Packet encoding/decoding
- `quinn-proto/src/crypto.rs` - Cryptographic operations
- `quinn-proto/src/frame.rs` - Frame types
- `quinn/examples/client.rs` - Client example

### RFCs
- RFC 9000 §17.2 - Long Header Packets
- RFC 9001 §5.4 - Header Protection
- RFC 9001 §5.3 - AEAD Usage
- RFC 8446 §4.1.3 - Server Hello

## 🎯 Next Session Goals

1. ✅ Server is stable (confirmed PID 3936879)
2. 🔄 Implement `decode_server_initial()` in packet.rs
3. 🔄 Implement HP removal for server packets
4. 🔄 Implement payload decryption
5. 🔄 Parse CRYPTO frame
6. 🔄 Extract TLS ServerHello

Once parser is complete, we can:
- Debug networking independently
- Test with captured packets
- Complete TLS handshake when networking works

**Estimated time to implement parser: 2-3 hours**
**Then: HTTP/3 is just frames away!** 🚀
