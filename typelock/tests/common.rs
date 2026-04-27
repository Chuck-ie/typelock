use typelock::{
    CryptoProvider, DigestProvider, IndexProvider, MacProvider, SecretProvider, SignProvider,
};

pub struct PolicyProvider;

impl IndexProvider for PolicyProvider {
    fn index(&self, data: &[u8]) -> Result<Vec<u8>, typelock::Error> {
        let mut out = b"indexed:".to_vec();
        out.extend_from_slice(data);
        Ok(out)
    }
}

impl CryptoProvider for PolicyProvider {
    fn encrypt(&self, data: &[u8]) -> std::result::Result<Vec<u8>, typelock::Error> {
        let mut out = b"encrypted:".to_vec();
        out.extend_from_slice(data);
        Ok(out)
    }

    fn decrypt(&self, data: &[u8]) -> std::result::Result<Vec<u8>, typelock::Error> {
        data.strip_prefix(b"encrypted:")
            .map(|payload| payload.to_vec())
            .ok_or_else(|| typelock::Error::Decryption("could not decrypt".to_string()))
    }
}

impl SecretProvider for PolicyProvider {
    fn hash_secret(&self, data: &[u8]) -> std::result::Result<Vec<u8>, typelock::Error> {
        let mut out = b"secret:".to_vec();
        out.extend_from_slice(data);
        Ok(out)
    }
}

impl DigestProvider for PolicyProvider {
    fn digest(&self, data: &[u8]) -> Result<Vec<u8>, typelock::Error> {
        let mut out = b"digest:".to_vec();
        out.extend_from_slice(data);
        Ok(out)
    }
}

impl SignProvider for PolicyProvider {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, typelock::Error> {
        let mut out = b"sig:".to_vec();
        out.extend_from_slice(data);
        Ok(out)
    }

    fn verify_signature(&self, data: &[u8]) -> Result<Vec<u8>, typelock::Error> {
        data.strip_prefix(b"sig:")
            .map(|payload| payload.to_vec())
            .ok_or_else(|| typelock::Error::SignatureVerification("invalid signature".to_string()))
    }
}

impl MacProvider for PolicyProvider {
    fn tag(&self, data: &[u8]) -> Result<Vec<u8>, typelock::Error> {
        let mut out = b"mac:".to_vec();
        out.extend_from_slice(data);
        Ok(out)
    }

    fn verify_mac(&self, data: &[u8]) -> Result<Vec<u8>, typelock::Error> {
        data.strip_prefix(b"mac:")
            .map(|payload| payload.to_vec())
            .ok_or_else(|| typelock::Error::MacVerification("invalid mac".to_string()))
    }
}
