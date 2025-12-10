#!/usr/bin/env python3
"""
Analyze QUIC Initial packet hex dump field by field
Compare with RFC 9000 specification
"""

def analyze_quic_initial_packet(hex_string):
    """Parse QUIC Initial packet from hex string"""

    # Remove spaces and convert to bytes
    hex_clean = hex_string.replace(' ', '').replace('\n', '')
    packet = bytes.fromhex(hex_clean)

    print("=" * 70)
    print("QUIC INITIAL PACKET ANALYSIS")
    print("=" * 70)
    print(f"\nTotal packet length: {len(packet)} bytes\n")

    idx = 0

    # Byte 0: First byte (Long Header)
    first_byte = packet[idx]
    print(f"[{idx}] First Byte: 0x{first_byte:02x} = {first_byte:08b}b")
    print(f"    Bit 7 (Header Form):     {(first_byte >> 7) & 1} (1=Long Header)")
    print(f"    Bit 6 (Fixed Bit):       {(first_byte >> 6) & 1} (MUST be 1)")
    print(f"    Bits 5-4 (Packet Type):  {(first_byte >> 4) & 3} (0=Initial)")
    print(f"    Bits 3-2 (Reserved):     {(first_byte >> 2) & 3} (MUST be 00)")
    print(f"    Bits 1-0 (PN Length):    {first_byte & 3} (PN is {(first_byte & 3) + 1} bytes)")

    if (first_byte >> 2) & 3 != 0:
        print(f"    ⚠️  RESERVED BITS ERROR: {(first_byte >> 2) & 3} (should be 00)")

    idx += 1

    # Bytes 1-4: Version
    version = int.from_bytes(packet[idx:idx+4], 'big')
    print(f"\n[{idx}-{idx+3}] Version: 0x{version:08x}")
    if version == 1:
        print("    ✅ QUIC v1")
    idx += 4

    # Byte 5: DCID Length
    dcid_len = packet[idx]
    print(f"\n[{idx}] DCID Length: {dcid_len} bytes")
    idx += 1

    # DCID
    dcid = packet[idx:idx+dcid_len]
    print(f"[{idx}-{idx+dcid_len-1}] DCID: {dcid.hex()}")
    idx += dcid_len

    # SCID Length
    scid_len = packet[idx]
    print(f"\n[{idx}] SCID Length: {scid_len} bytes")
    idx += 1

    # SCID
    scid = packet[idx:idx+scid_len]
    print(f"[{idx}-{idx+scid_len-1}] SCID: {scid.hex()}")
    idx += scid_len

    # Token Length (varint)
    token_len = packet[idx]
    print(f"\n[{idx}] Token Length: {token_len}")
    idx += 1

    if token_len > 0:
        token = packet[idx:idx+token_len]
        print(f"[{idx}-{idx+token_len-1}] Token: {token.hex()}")
        idx += token_len

    # Length field (2-byte varint)
    length_byte1 = packet[idx]
    length_byte2 = packet[idx+1]

    # Decode 2-byte varint: 01xxxxxx yyyyyyyy
    payload_len = ((length_byte1 & 0x3f) << 8) | length_byte2
    print(f"\n[{idx}-{idx+1}] Payload Length: 0x{length_byte1:02x}{length_byte2:02x}")
    print(f"    Decoded: {payload_len} bytes (PN + Encrypted Payload)")
    idx += 2

    # Packet Number (protected!)
    pn_len = (first_byte & 3) + 1
    pn_bytes = packet[idx:idx+pn_len]
    print(f"\n[{idx}-{idx+pn_len-1}] Packet Number (PROTECTED): {pn_bytes.hex()}")
    print(f"    ⚠️  This is AFTER header protection - can't read actual PN")
    idx += pn_len

    # Encrypted payload
    encrypted_len = len(packet) - idx
    print(f"\n[{idx}-{len(packet)-1}] Encrypted Payload: {encrypted_len} bytes")
    print(f"    (includes AEAD authentication tag - last 16 bytes)")

    # Show first 32 bytes of ciphertext for analysis
    ciphertext_preview = packet[idx:idx+min(32, encrypted_len)]
    print(f"\n    First 32 bytes of ciphertext:")
    for i in range(0, len(ciphertext_preview), 16):
        chunk = ciphertext_preview[i:i+16]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        print(f"      {hex_str}")

    # Header Protection analysis
    pn_offset = idx - pn_len
    sample_offset = pn_offset + 4

    print(f"\n" + "=" * 70)
    print("HEADER PROTECTION ANALYSIS")
    print("=" * 70)
    print(f"PN offset: {pn_offset}")
    print(f"Sample offset (PN offset + 4): {sample_offset}")

    if sample_offset + 16 <= len(packet):
        sample = packet[sample_offset:sample_offset+16]
        print(f"\nSample (16 bytes at offset {sample_offset}):")
        print(f"  {sample.hex()}")

        # This should match ciphertext[2:18]
        ciphertext_start = idx
        expected_sample = packet[ciphertext_start+2:ciphertext_start+18]
        print(f"\nExpected (ciphertext[2:18]):")
        print(f"  {expected_sample.hex()}")

        if sample == expected_sample:
            print("  ✅ Sample extraction is correct!")
        else:
            print("  ❌ Sample mismatch!")

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"✅ Packet structure looks valid")
    print(f"✅ DCID: {dcid.hex()} ({len(dcid)} bytes)")
    print(f"✅ Total size: {len(packet)} bytes")

    reserved_bits = (first_byte >> 2) & 3
    if reserved_bits != 0:
        print(f"❌ PROBLEM: Reserved bits = {reserved_bits} (MUST be 00)")
        print(f"   This will cause 'invalid reserved bits' error!")
    else:
        print(f"✅ Reserved bits = 00 (correct)")

    print()

if __name__ == "__main__":
    # Latest packet from test_quinn_local
    packet_hex = """
    c7000000011441c42f86b02a55e4c40a7431d29d1f3c74bf4a01085aaf9c39417768f200448a089cb27c9ce1d7e5b0dd56b6353a43b95446ab377f24a9da3b88dd3b8ac87629b047569c38f76011d26a8ccc43724ae7767e5894f677df77eea2958ab0db9f6a09e39aa0cceeba35267b16b02ef3a1ffd90d3ac680df10de0f07f019dc34099d232a91b3befa17fb85c133edd27ad173510c6c60377a0cdd7262550d4a497a389f23310bbd3710795c6718d782248248e049579af826b7f1fed16a8e59d09e32303f66d8a8570609ca9d0897ab03a63ff7c86ed9a063d910faa575a94427d2417b414ea8c550423636957ae7a1e48bb439fe7af7fa264811d8ff25510a7868a806b098ee5a413cad51eb1ee4ccebd16a69194e9f08b91003971faded165083b213dcb35f8e10f6c4c6965eff007472938f2779eb8f175e6f7c6143188798acc13dfbe7c0d0c0b73ee63fa53e10d08f74eb81ad53f906a85f1aa74af3204674b472ff849b86f23a8f63bdebdc42d60aba6b8e887175ca4636ddaee2af62158990c6dd88ceddbe91ebe8fbeb26f367e22c1035c613bd58bb04d3d28705415a6df43da9e546371b7267228286daef8442c27f75ea301bed3b027e1ec03b2f98bd5f6aac5c8aed980640c262c74c57e8a03ea9662c0055a40e684227fb50b47edbcabccb1d30709bf7d9c082d94570ccb6708440407a93d96ac7228845c21ad9eb584ecaaecf8b0ceeccbbd150c0ddb460a5ac8d0da49039731d267e3aac9ac28ddad408c1eb7f4dd63860a63ca66c8256e872dde3a5c06d75d46c9f745d0d06351635a91dead558453e49b665ee92df9fe6f8bc0f6e2c3375001e0261a872e6f21a7ea40b722843641b5b19c079dda9c3ba86784dbbec48e60ba7396126eaa7e4d01331934987799abf1ec31bdc2224bcfa1e1d5e14db3b73fe4b5585649493af630febf897173d3af860b236fea3dcc2053290948eafed70d6bb8192281035f0ddfe9f867d028be668d1d479bf22b89f1b62636f58e17833e2a12e8ab0511757a3caf85c89bf788f4cc77899156bcf4bb22cc902c0ee60657a571ce297e8687e53f57631c71838aa33adf4106f89c7f994ee9978f20b1209d7fbd410b9e72968111f864209e568ff421399a6d7125ba8165f72bcb3368ad3c59baea56846dc81ec4b6a2b4e0c2be6679be109c0f98f94e4f6c0b0713d05cb82c7dfeed9d9eb8b000258fdc23a435966d4417bb7aab50f27b9276fb72ea54a62db6edf2b025ded0c04ddf0d450be00e4e265efbf8bc67c0e9b7d67fcab14d72949394ba392d954224263525d7128eb8edfb2b2fff2631939c9813004c14f01330e1e8944c6693a5d695f88691ceb791d069e0e2b1507e5911686112b91012a4b3a48e6a25a04332b804f0b3ab271bf0bd45a2ad0663bd1a314ce90e0a8c57af3c00b895d8a69d4db72d48a00ff458ea5127367086c1c0fd171e4c4135d5177d8b4fd04fec487b356858af776e1b18ed1ccda8bf0e69a3e711c947daf2cef2d77a6ccd0e3551f8565ea2849045d864596254d0d3d7c0c1dc28fbebfd7e441591e8425f5a9cbe3b3839834810c8af7bb29e5ecc329183399dd9283e651496d6441cb117fa0728af5008445c00b7d9f3c5aac9e0075f023d6927c048aee13b40ca479b319a7a0b4c7a4146163eaa5bc56ab984f
    """

    analyze_quic_initial_packet(packet_hex)
