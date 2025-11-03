# 🔐 Crypto Implementation Progress

## ✅ Implementado (100% do zero em Rust std)

### 1. SHA-256 (175 linhas)
**Arquivo**: `src/crypto/sha256.rs`

- ✅ Implementação completa do algoritmo SHA-256
- ✅ Segue RFC 6234 (US Secure Hash Algorithms)
- ✅ Suporta mensagens de qualquer tamanho
- ✅ 3 testes unitários (vetores de teste oficiais)

**Funcionalidades**:
```rust
let hash = sha256(b"data");  // [u8; 32]
```

---

### 2. HMAC-SHA256 (100 linhas)
**Arquivo**: `src/crypto/hmac.rs`

- ✅ Hash-based Message Authentication Code
- ✅ Segue RFC 2104 (HMAC spec)
- ✅ Usa SHA-256 como hash function
- ✅ 2 testes unitários (RFC 4231 test vectors)

**Funcionalidades**:
```rust
let mac = hmac_sha256(key, message);  // [u8; 32]
```

---

### 3. PRF TLS 1.2 (120 linhas)
**Arquivo**: `src/crypto/prf.rs`

- ✅ Pseudo-Random Function do TLS 1.2
- ✅ Segue RFC 5246 Section 5
- ✅ P_SHA256 expansion function
- ✅ Master Secret derivation
- ✅ Key expansion (key_block generation)
- ✅ 3 testes unitários

**Funcionalidades**:
```rust
// Gerar master secret
let master = derive_master_secret(&pre_master, &client_random, &server_random);

// Gerar chaves de criptografia
let keys = derive_keys(&master_secret, &server_random, &client_random, 104);
```

---

### 4. AES-128-CBC (450 linhas)
**Arquivo**: `src/crypto/aes.rs`

- ✅ Advanced Encryption Standard (128-bit)
- ✅ Segue FIPS-197 spec
- ✅ Modo CBC (Cipher Block Chaining)
- ✅ PKCS#7 padding
- ✅ S-box e Inverse S-box
- ✅ Key expansion (11 round keys)
- ✅ SubBytes, ShiftRows, MixColumns
- ✅ Galois Field multiplication
- ✅ 2 testes unitários

**Funcionalidades**:
```rust
// Encrypt
let ciphertext = aes128_cbc_encrypt(&key, &iv, plaintext);

// Decrypt
let plaintext = aes128_cbc_decrypt(&key, &iv, &ciphertext)?;
```

---

## 📊 Estatísticas

| Componente | Linhas | Testes | Status |
|------------|--------|--------|--------|
| SHA-256 | 175 | 3 | ✅ COMPLETE |
| HMAC-SHA256 | 100 | 2 | ✅ COMPLETE |
| PRF TLS 1.2 | 120 | 3 | ✅ COMPLETE |
| AES-128-CBC | 450 | 2 | ✅ COMPLETE |
| **TOTAL** | **845 linhas** | **10 testes** | **✅ DONE** |

---

## 🎯 O que isso permite

Com esses 4 componentes, agora podemos:

1. ✅ **Derivar Master Secret** do pre-master secret
2. ✅ **Derivar chaves simétricas** (client/server write keys + MACs)
3. ✅ **Criptografar dados** em modo CBC
4. ✅ **Descriptografar dados** recebidos
5. ✅ **Calcular HMACs** para integridade

---

## ⏳ O que ainda falta

### 1. RSA para ClientKeyExchange (~300 linhas)
**Necessário para**:
- Criptografar pre-master secret com chave pública do servidor
- Extrair chave pública do certificado X.509

**Alternativa**: Por enquanto, podemos usar pre-master secret fixo (inseguro mas funcional para testes)

### 2. Integração no TLS module
**Necessário**:
- Armazenar client_random, server_random, pre_master_secret
- Derivar master_secret após handshake
- Derivar keys após ChangeCipherSpec
- Usar AES-128-CBC no Read/Write traits

### 3. HMAC verification
**Necessário**:
- Calcular HMAC dos registros TLS
- Verificar HMAC ao descriptografar
- Incluir sequence number (anti-replay)

---

## 🚀 Próximos passos

### Opção A: Implementar RSA completo (~300 linhas)
```rust
// src/crypto/rsa.rs
pub fn rsa_encrypt(pubkey: &RsaPublicKey, data: &[u8]) -> Vec<u8>;
pub fn parse_x509_pubkey(cert: &[u8]) -> Result<RsaPublicKey, String>;
```

**Prós**:
- ✅ ZERO dependências externas
- ✅ Implementação completa do TLS

**Contras**:
- ❌ 2-3 dias de trabalho
- ❌ Complexo (big integers, modular exponentiation)

### Opção B: Pre-master fixo + testar (RÁPIDO)
```rust
// Hardcode pre-master temporariamente
let pre_master = [0x03, 0x03, /* 46 random bytes */];
// Servidor vai rejeitar MAS podemos testar a criptografia!
```

**Prós**:
- ✅ Testar agora mesmo
- ✅ Validar AES/HMAC/PRF

**Contras**:
- ❌ Não funciona com servidores reais
- ❌ Apenas para testes internos

---

## 💡 Recomendação

**Implementar opção B primeiro (30min) para validar toda a stack crypto**, depois decidir se vale implementar RSA completo ou usar solução híbrida.

---

## 📝 Código necessário para integração

```rust
// Em src/modules/network/tls.rs

use crate::crypto::{prf, aes, hmac};

pub struct TlsStream {
    stream: TcpStream,
    // ... existing fields ...

    // NEW: Crypto state
    client_random: [u8; 32],
    server_random: [u8; 32],
    master_secret: Option<[u8; 48]>,
    client_write_key: Option<[u8; 16]>,
    server_write_key: Option<[u8; 16]>,
    client_write_mac: Option<[u8; 20]>,  // SHA-1 HMAC for TLS 1.2
    server_write_mac: Option<[u8; 20]>,
    client_sequence: u64,
    server_sequence: u64,
}

fn handshake(&mut self, host: &str) -> Result<(), String> {
    // 1. ClientHello
    self.client_random = generate_random_32();
    self.send_client_hello(host)?;

    // 2. ServerHello
    let server_hello = self.receive_server_hello()?;
    self.server_random = parse_server_random(&server_hello);

    // 3. Certificate
    let cert = self.receive_certificate()?;
    // let pubkey = parse_x509_pubkey(&cert)?; // TODO: RSA

    // 4. ServerHelloDone
    self.receive_server_hello_done()?;

    // 5. ClientKeyExchange
    let pre_master = [0x03, 0x03 /* + 46 random bytes */];
    // let encrypted = rsa_encrypt(&pubkey, &pre_master); // TODO: RSA
    self.send_client_key_exchange(&pre_master)?;

    // 6. Derive keys
    self.master_secret = Some(prf::derive_master_secret(
        &pre_master,
        &self.client_random,
        &self.server_random
    ));

    let key_material = prf::derive_keys(
        &self.master_secret.unwrap(),
        &self.server_random,
        &self.client_random,
        104  // 2*20 (MAC) + 2*16 (key) + 2*16 (IV)
    );

    // Extract keys from key_block
    let mut offset = 0;
    self.client_write_mac = Some(key_material[offset..offset+20].try_into().unwrap());
    offset += 20;
    self.server_write_mac = Some(key_material[offset..offset+20].try_into().unwrap());
    offset += 20;
    self.client_write_key = Some(key_material[offset..offset+16].try_into().unwrap());
    offset += 16;
    self.server_write_key = Some(key_material[offset..offset+16].try_into().unwrap());
    // ... continue for IVs ...

    // 7-9. ChangeCipherSpec + Finished
    // ... rest of handshake ...
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Encrypt with AES-128-CBC
        let key = self.client_write_key.unwrap();
        let iv = /* ... */;
        let encrypted = aes::aes128_cbc_encrypt(&key, &iv, buf);

        // Wrap in TLS record
        let record = wrap_tls_record(ContentType::ApplicationData, &encrypted);
        self.stream.write_all(&record)?;
        Ok(buf.len())
    }
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // ... read TLS record ...

        // Decrypt with AES-128-CBC
        let key = self.server_write_key.unwrap();
        let decrypted = aes::aes128_cbc_decrypt(&key, &iv, &payload)?;

        // Copy to buffer
        let to_copy = buf.len().min(decrypted.len());
        buf[..to_copy].copy_from_slice(&decrypted[..to_copy]);
        Ok(to_copy)
    }
}
```

---

## 🎉 Conclusão

**Implementamos 845 linhas de criptografia pura do zero!**

- ✅ SHA-256
- ✅ HMAC-SHA256
- ✅ PRF TLS 1.2
- ✅ AES-128-CBC

Falta apenas:
- ⏳ RSA (~300 linhas) OU pre-master fixo para testes
- ⏳ Integração no TLS module (~200 linhas)

**TOTAL estimado para HTTPS 100% funcional: ~1400 linhas - já fizemos 60%!** 🚀
