use crate::{
    types::{Decrypted, Verified},
    Error,
};

pub trait IndexProvider {
    /// Produce an index based on some data e.g. with blake3
    fn index(&self, data: &[u8]) -> Result<Vec<u8>, Error>;
}

pub trait CryptoProvider {
    /// Encrypt a plaintext byte slice.
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error>;

    /// Decrypt an encrypted byte slice back into plaintext bytes.
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error>;
}

pub trait SecretProvider {
    /// Produce a one-way secret hash (for example, password hashing).
    fn hash_secret(&self, data: &[u8]) -> Result<Vec<u8>, Error>;
}

pub trait DigestProvider {
    /// Compute a digest of the input bytes.
    fn digest(&self, data: &[u8]) -> Result<Vec<u8>, Error>;
}

pub trait SignProvider {
    /// Produce a signed payload from raw bytes.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error>;

    /// Verify and recover the signed payload bytes.
    fn verify_signature(&self, data: &[u8]) -> Result<Vec<u8>, Error>;
}

pub trait MacProvider {
    /// Attach a MAC tag to raw bytes.
    fn tag(&self, data: &[u8]) -> Result<Vec<u8>, Error>;

    /// Verify and recover MAC-tagged payload bytes.
    fn verify_mac(&self, data: &[u8]) -> Result<Vec<u8>, Error>;
}

/// Trait for types that can be transformed into their locked representation.
///
/// Depending on field policy, locking may encrypt, hash, digest, sign, or MAC-tag data.
pub trait Lockable<P> {
    type Output;

    fn lock(self, provider: &P) -> Result<Self::Output, Error>;
}

impl<P, T> Lockable<P> for Vec<T>
where
    T: Lockable<P>,
{
    type Output = Vec<T::Output>;

    #[inline]
    fn lock(self, provider: &P) -> Result<Self::Output, Error> {
        self.into_iter().map(|m| m.lock(provider)).collect()
    }
}

/// Trait for types that can be transformed into their unlocked representation.
///
/// Depending on field policy, unlocking may decrypt or verify signed/MAC-tagged bytes,
/// while one-way policies (secret hash and digest) remain in their wrapped form.
pub trait Unlockable<P> {
    type Output;

    fn unlock(self, provider: &P) -> Result<Self::Output, Error>;
}

impl<P, T> Unlockable<P> for Vec<T>
where
    T: Unlockable<P>,
{
    type Output = Vec<T::Output>;

    #[inline]
    fn unlock(self, provider: &P) -> Result<Self::Output, Error> {
        self.into_iter().map(|m| m.unlock(provider)).collect()
    }
}

/// Trait for serializing values into bytes for provider operations.
pub trait ToBytes {
    fn to_bytes(&self) -> Result<Vec<u8>, Error>;
}

impl ToBytes for String {
    fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(self.as_bytes().to_vec())
    }
}

impl ToBytes for Vec<u8> {
    fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(self.to_owned())
    }
}

impl<T> ToBytes for Decrypted<T>
where
    T: ToBytes,
{
    fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        (**self).to_bytes()
    }
}

impl<T> ToBytes for Verified<T>
where
    T: ToBytes,
{
    fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        (**self).to_bytes()
    }
}

/// Trait for deserializing bytes back into strongly typed values.
pub trait FromBytes: Sized {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error>;
}

impl FromBytes for String {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(String::from_utf8(bytes.to_vec())?)
    }
}

impl FromBytes for Vec<u8> {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(bytes.to_owned())
    }
}
