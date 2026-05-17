use crate::{Result, VpnError};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};

#[derive(Clone)]
pub struct OlcCipher {
    aead: XChaCha20Poly1305,
}

impl OlcCipher {
    pub fn from_hex(key_hex: &str) -> Result<Self> {
        let key = decode_hex_32(key_hex)?;
        Ok(Self {
            aead: XChaCha20Poly1305::new(key.as_slice().into()),
        })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0_u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let mut out = nonce.to_vec();
        let encrypted = self
            .aead
            .encrypt(XNonce::from_slice(&nonce), plaintext)
            .map_err(|error| VpnError::Engine(format!("OLC RTC encrypt failed: {error}")))?;
        out.extend(encrypted);
        Ok(out)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 24 {
            return Err(VpnError::Engine(
                "OLC RTC ciphertext shorter than nonce".into(),
            ));
        }
        let nonce = XNonce::from_slice(&ciphertext[..24]);
        self.aead
            .decrypt(nonce, &ciphertext[24..])
            .map_err(|error| VpnError::Engine(format!("OLC RTC decrypt failed: {error}")))
    }
}

fn decode_hex_32(input: &str) -> Result<[u8; 32]> {
    if input.len() != 64 {
        return Err(VpnError::InvalidProfile(
            "OLC RTC shared key must be a 32-byte hex string".into(),
        ));
    }

    let mut bytes = [0_u8; 32];
    for index in 0..32 {
        bytes[index] = u8::from_str_radix(&input[index * 2..index * 2 + 2], 16).map_err(|_| {
            VpnError::InvalidProfile("OLC RTC shared key must be hexadecimal".into())
        })?;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::OlcCipher;

    #[test]
    fn round_trips_olcrtc_ciphertext() {
        let cipher =
            OlcCipher::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .unwrap();

        let encrypted = cipher.encrypt(b"hello").unwrap();
        assert_ne!(encrypted, b"hello");
        assert_eq!(cipher.decrypt(&encrypted).unwrap(), b"hello");
    }
}
