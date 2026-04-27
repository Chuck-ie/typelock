use diesel::{
    backend::Backend,
    deserialize::FromSql,
    serialize::{Output, ToSql},
    sql_types::Binary,
};

use crate::{Digested, Encrypted, Indexed, Secret, Signed, Tagged};

// =============================================================================
// DIESEL IMPLEMENTATIONS — LOCKED TYPES ONLY
// =============================================================================
// Only locked wrapper types (Encrypted, Hashed, Digested, Signed, Tagged)
// implement diesel's FromSql/ToSql traits.
//
// Unlocked types (Decrypted, Verified) are INTENTIONALLY excluded.
//
// Rationale: unlocked types represent sensitive data in its usable form —
// plaintext, verified payloads, decrypted secrets. They should never be
// written to a database directly. If you find yourself needing to store
// an unlocked type, you almost certainly want to call `.lock()` first.
//
// If diesel impls on unlocked types are ever added, it should be treated
// as a security regression and reverted.
// =============================================================================

macro_rules! impl_from_and_to_sql {
    ($name:ident) => {
        impl<T, DB> FromSql<Binary, DB> for $name<T>
        where
            DB: Backend,
            Vec<u8>: FromSql<Binary, DB>,
        {
            fn from_sql(bytes: DB::RawValue<'_>) -> diesel::deserialize::Result<Self> {
                Ok(Self::new(Vec::<u8>::from_sql(bytes)?))
            }
        }

        impl<T, DB> ToSql<Binary, DB> for $name<T>
        where
            T: std::fmt::Debug,
            DB: Backend,
            Vec<u8>: ToSql<Binary, DB>,
        {
            fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, DB>) -> diesel::serialize::Result {
                self.bytes.to_sql(out)
            }
        }
    };
}

impl_from_and_to_sql!(Indexed);
impl_from_and_to_sql!(Encrypted);
impl_from_and_to_sql!(Secret);
impl_from_and_to_sql!(Digested);
impl_from_and_to_sql!(Signed);
impl_from_and_to_sql!(Tagged);

// /// implemenations for Encrypted
// impl<T, DB> FromSql<Binary, DB> for Encrypted<T>
// where
//     DB: Backend,
//     Vec<u8>: FromSql<Binary, DB>,
// {
//     fn from_sql(bytes: DB::RawValue<'_>) -> diesel::deserialize::Result<Self> {
//         Ok(Self::new(Vec::<u8>::from_sql(bytes)?))
//     }
// }
//
// impl<T, DB> ToSql<Binary, DB> for Encrypted<T>
// where
//     T: std::fmt::Debug,
//     DB: Backend,
//     Vec<u8>: ToSql<Binary, DB>,
// {
//     fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, DB>) -> diesel::serialize::Result {
//         self.bytes.to_sql(out)
//     }
// }
//
// /// implemenations for Secret
// impl<T, DB> FromSql<Binary, DB> for Secret<T>
// where
//     DB: Backend,
//     Vec<u8>: FromSql<Binary, DB>,
// {
//     fn from_sql(bytes: DB::RawValue<'_>) -> diesel::deserialize::Result<Self> {
//         Ok(Self::new(Vec::<u8>::from_sql(bytes)?))
//     }
// }
//
// impl<T, DB> ToSql<Binary, DB> for Secret<T>
// where
//     T: std::fmt::Debug,
//     DB: Backend,
//     Vec<u8>: ToSql<Binary, DB>,
// {
//     fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, DB>) -> diesel::serialize::Result {
//         self.bytes.to_sql(out)
//     }
// }
//
// /// implemenations for Digested
// impl<T, DB> FromSql<Binary, DB> for Digested<T>
// where
//     DB: Backend,
//     Vec<u8>: FromSql<Binary, DB>,
// {
//     fn from_sql(bytes: DB::RawValue<'_>) -> diesel::deserialize::Result<Self> {
//         Ok(Self::new(Vec::<u8>::from_sql(bytes)?))
//     }
// }
//
// impl<T, DB> ToSql<Binary, DB> for Digested<T>
// where
//     T: std::fmt::Debug,
//     DB: Backend,
//     Vec<u8>: ToSql<Binary, DB>,
// {
//     fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, DB>) -> diesel::serialize::Result {
//         self.bytes.to_sql(out)
//     }
// }
//
// /// implemenations for Signed
// impl<T, DB> FromSql<Binary, DB> for Signed<T>
// where
//     DB: Backend,
//     Vec<u8>: FromSql<Binary, DB>,
// {
//     fn from_sql(bytes: DB::RawValue<'_>) -> diesel::deserialize::Result<Self> {
//         Ok(Self::new(Vec::<u8>::from_sql(bytes)?))
//     }
// }
//
// impl<T, DB> ToSql<Binary, DB> for Signed<T>
// where
//     T: std::fmt::Debug,
//     DB: Backend,
//     Vec<u8>: ToSql<Binary, DB>,
// {
//     fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, DB>) -> diesel::serialize::Result {
//         self.bytes.to_sql(out)
//     }
// }
//
// /// implemenations for Tagged
// impl<T, DB> FromSql<Binary, DB> for Tagged<T>
// where
//     DB: Backend,
//     Vec<u8>: FromSql<Binary, DB>,
// {
//     fn from_sql(bytes: DB::RawValue<'_>) -> diesel::deserialize::Result<Self> {
//         Ok(Self::new(Vec::<u8>::from_sql(bytes)?))
//     }
// }
//
// impl<T, DB> ToSql<Binary, DB> for Tagged<T>
// where
//     T: std::fmt::Debug,
//     DB: Backend,
//     Vec<u8>: ToSql<Binary, DB>,
// {
//     fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, DB>) -> diesel::serialize::Result {
//         self.bytes.to_sql(out)
//     }
// }
