use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct PasswordHasherService {
    engine: Argon2<'static>,
}

impl Default for PasswordHasherService {
    fn default() -> Self {
        Self {
            engine: Argon2::default(),
        }
    }
}

impl PasswordHasherService {
    pub fn hash_password(&self, password: &str) -> Result<String, CryptoError> {
        let salt = SaltString::generate(&mut OsRng);
        Ok(self.engine.hash_password(password.as_bytes(), &salt)?.to_string())
    }

    pub fn verify_password(&self, password: &str, hash: &str) -> Result<(), CryptoError> {
        let parsed = PasswordHash::new(hash)?;
        self.engine.verify_password(password.as_bytes(), &parsed)?;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("password hash error")]
    PasswordHash(#[from] argon2::password_hash::Error),
}

#[derive(Debug, Clone, Default)]
pub struct OpaqueTokenService;

impl OpaqueTokenService {
    pub fn generate(&self, bytes_len: usize) -> String {
        let mut bytes = vec![0_u8; bytes_len];
        OsRng.fill_bytes(&mut bytes);
        Base64UrlUnpadded::encode_string(&bytes)
    }

    pub fn sha256(&self, value: &str) -> String {
        let digest = Sha256::digest(value.as_bytes());
        Base64UrlUnpadded::encode_string(&digest)
    }
}

#[cfg(test)]
mod tests {
    use super::{OpaqueTokenService, PasswordHasherService};

    #[test]
    fn password_roundtrip_succeeds() {
        let service = PasswordHasherService::default();
        let hash = service.hash_password("correct horse battery staple").expect("hash");

        service
            .verify_password("correct horse battery staple", &hash)
            .expect("verify");
    }

    #[test]
    fn wrong_password_is_rejected() {
        let service = PasswordHasherService::default();
        let hash = service.hash_password("correct horse battery staple").expect("hash");

        let result = service.verify_password("wrong password", &hash);
        assert!(result.is_err());
    }

    #[test]
    fn opaque_token_hash_is_stable() {
        let service = OpaqueTokenService;
        let token = service.generate(32);

        assert_eq!(service.sha256(&token), service.sha256(&token));
    }
}
