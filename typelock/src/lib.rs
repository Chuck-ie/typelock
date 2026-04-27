pub use typelock_derive::LockSchema;

#[cfg(feature = "wincode-codec")]
pub use typelock_derive::{FromBytes, ToBytes};
#[cfg(feature = "wincode-codec")]
pub use wincode;

mod error;
mod traits;
mod types;

#[cfg(feature = "diesel")]
mod diesel_impl;

// Re-export core types and traits
pub use error::Error;
pub use traits::{
    CryptoProvider, DigestProvider, IndexProvider, MacProvider, SecretProvider, SignProvider,
};
pub use traits::{FromBytes, ToBytes};
pub use traits::{Lockable, Unlockable};

#[doc(hidden)]
pub use types::{Decrypted, Digested, Encrypted, Indexed, Secret, Signed, Tagged, Verified};
