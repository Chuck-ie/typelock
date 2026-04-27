use std::{
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

/// A typed wrapper for index data.
///
/// This type should only be created through the `LockSchema` derive macro.
/// It is hidden from public documentation but accessible to the macro.
#[doc(hidden)]
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "diesel", derive(diesel::AsExpression, diesel::FromSqlRow))]
#[cfg_attr(feature = "diesel", diesel(sql_type = diesel::sql_types::Binary))]
pub struct Indexed<T> {
    pub bytes: Vec<u8>,
    _marker: PhantomData<T>,
}

impl<T> Indexed<T> {
    #[doc(hidden)]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            _marker: PhantomData::<T>,
        }
    }
}

impl<T> Deref for Indexed<T> {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

/// A typed wrapper for encrypted bytes.
///
/// This type should only be created through the `LockSchema` derive macro.
/// It is hidden from public documentation but accessible to the macro.
#[doc(hidden)]
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "diesel", derive(diesel::AsExpression, diesel::FromSqlRow))]
#[cfg_attr(feature = "diesel", diesel(sql_type = diesel::sql_types::Binary))]
pub struct Encrypted<T> {
    pub bytes: Vec<u8>,
    _marker: PhantomData<T>,
}

impl<T> Encrypted<T> {
    #[doc(hidden)]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            _marker: PhantomData::<T>,
        }
    }
}

impl<T> Deref for Encrypted<T> {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

/// A typed wrapper for decrypted data.
///
/// This type should only be created through the `LockSchema` derive macro.
/// It is hidden from public documentation but accessible to the macro.
#[doc(hidden)]
#[derive(Debug, PartialEq, Eq)]
pub struct Decrypted<T> {
    pub data: T,
}

impl<T> Decrypted<T> {
    #[doc(hidden)]
    pub fn new(data: T) -> Self {
        Self { data }
    }
}

impl<T> Deref for Decrypted<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T> DerefMut for Decrypted<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

/// A typed wrapper for one-way secret-hashed bytes.
///
/// This type should only be created through the `LockSchema` derive macro.
/// It is hidden from public documentation but accessible to the macro.
#[doc(hidden)]
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "diesel", derive(diesel::AsExpression, diesel::FromSqlRow))]
#[cfg_attr(feature = "diesel", diesel(sql_type = diesel::sql_types::Binary))]
pub struct Secret<T> {
    pub bytes: Vec<u8>,
    _marker: PhantomData<T>,
}

impl<T> Secret<T> {
    #[doc(hidden)]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            _marker: PhantomData::<T>,
        }
    }
}

impl<T> Deref for Secret<T> {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

/// A typed wrapper for digest bytes.
///
/// This represents the `Digest` policy where data is hashed.
/// It is used for both the locked and unlocked states since hashes are irreversible.
#[doc(hidden)]
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "diesel", derive(diesel::AsExpression, diesel::FromSqlRow))]
#[cfg_attr(feature = "diesel", diesel(sql_type = diesel::sql_types::Binary))]
pub struct Digested<T> {
    pub bytes: Vec<u8>,
    _marker: PhantomData<T>,
}

impl<T> Digested<T> {
    #[doc(hidden)]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            _marker: PhantomData::<T>,
        }
    }
}

impl<T> Deref for Digested<T> {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

/// A typed wrapper for signed payload bytes.
///
/// This represents the locked state of the `Sign` policy.
#[doc(hidden)]
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "diesel", derive(diesel::AsExpression, diesel::FromSqlRow))]
#[cfg_attr(feature = "diesel", diesel(sql_type = diesel::sql_types::Binary))]
pub struct Signed<T> {
    pub bytes: Vec<u8>,
    _marker: PhantomData<T>,
}

impl<T> Signed<T> {
    #[doc(hidden)]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            _marker: PhantomData::<T>,
        }
    }
}

impl<T> Deref for Signed<T> {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

/// A typed wrapper for MAC (Message Authentication Code) tagged bytes.
///
/// This represents the locked state of the `Mac` policy.
#[doc(hidden)]
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "diesel", derive(diesel::AsExpression, diesel::FromSqlRow))]
#[cfg_attr(feature = "diesel", diesel(sql_type = diesel::sql_types::Binary))]
pub struct Tagged<T> {
    pub bytes: Vec<u8>,
    _marker: PhantomData<T>,
}

impl<T> Tagged<T> {
    #[doc(hidden)]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            _marker: PhantomData::<T>,
        }
    }
}

impl<T> Deref for Tagged<T> {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

/// A typed wrapper for verified data from `Sign`/`Mac` policies.
///
/// This is used as the unlocked representation for `Sign` and `Mac` fields.
/// The inner value is the decoded high-level type (`T`), produced after
/// provider verification and `FromBytes` conversion.
#[doc(hidden)]
#[derive(Debug, PartialEq, Eq)]
pub struct Verified<T> {
    pub data: T,
}

impl<T> Verified<T> {
    #[doc(hidden)]
    pub fn new(data: T) -> Self {
        Self { data }
    }
}

impl<T> Deref for Verified<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T> DerefMut for Verified<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}
