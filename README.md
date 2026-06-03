# Typelock
[![CI](https://github.com/Chuck-ie/typelock/actions/workflows/rust.yml/badge.svg)](https://github.com/Chuck-ie/typelock/actions/workflows/rust.yml)
[![crates.io](https://img.shields.io/crates/v/typelock.svg)](https://crates.io/crates/typelock)
[![docs.rs](https://docs.rs/typelock/badge.svg)](https://docs.rs/typelock)

## About
**Enforce security boundaries at the Type level**

`typelock` is a Rust framework for creating type-safe secured data models. It uses a procedural macro to generate locked and unlocked versions of your data models so sensitive data is only accessible through explicit model conversion steps.

## Status
`typelock` is in active development and the API may change between versions. Make sure to pin your version if you're going to use it.

If you plan to adopt it today, pinning to a specific version is recommended.

## Features
Given a single input definition, `typelock` generates the following:
- An **unlocked** representation 
- A **locked** representation
- Explicit `lock()` and `unlock()` transitions, based on the current model
- Field policies for `encrypt`, `secret`, `digest`, `sign`, and `mac`
- Optional **ToBytes/FromBytes derive macros** via the `wincode-codec` feature
- Optional **Diesel integration** for direct database storage of locked fields

## Planned
- Memory zeroing via [`zeroize`](https://crates.io/crates/zeroize) and [`secrecy`](https://crates.io/crates/secrecy) for sensitive fields on drop
- Compile-time prevention of `Clone` on secured models to avoid accidental data leaks

## Example
```rust
#[derive(LockSchema, Clone)]
#[typelock(unlocked(name = UserUnlocked, derives(Debug)), locked(name = UserLocked))]
pub struct User {
    pub id: i64,

    #[secure(policy(encrypt))]
    pub email: String,

    #[secure(policy(secret), rename = "password_hash")]
    pub password: String,

    #[secure(policy(encrypt))]
    pub user_data: UserData,
}
```

## Custom types
Secured fields must define how they are converted to and from bytes. This is intentional, so that `typelock` does not force you into using a specific serialization library.

```rust
#[derive(Debug, Clone)]
pub struct UserData {
    first_name: String,
}

impl ToBytes for UserData {
    fn to_bytes(&self) -> Result<Vec<u8>, typelock::Error> {
        Ok(self.first_name.as_bytes().to_vec())
    }
}

impl FromBytes for UserData {
    fn from_bytes(bytes: &[u8]) -> Result<Self, typelock::Error> {
        Ok(Self {
            first_name: String::from_utf8(bytes.to_vec())?,
        })
    }
}
```

`typelock` includes `ToBytes`/`FromBytes` implementations for `String` and `Vec<u8>` out of the box.

You can also enable the `wincode-codec` feature to use the `#[derive(ToBytes, FromBytes)]` macros. Those derives generate byte conversion implementations using [wincode](https://crates.io/crates/wincode), so you can avoid writing manual conversion code for custom data types.

## Security providers
To stay flexible, `typelock` is intentionally backend agnostic. You provide your own implementation for the policy traits your model uses:

```rust
pub struct MySecurityProvider;

// CryptoProvider for encrypt/decrypt fields
impl typelock::CryptoProvider for MySecurityProvider {
    fn encrypt(&self, data: &[u8]) -> std::result::Result<Vec<u8>, typelock::Error> {
        todo!("implement your own encryption logic here.")
    }

    fn decrypt(&self, data: &[u8]) -> std::result::Result<Vec<u8>, typelock::Error> {
        todo!("implement your own decryption logic here.")
    }
}

// SecretProvider for one-way secret hashing
impl typelock::SecretProvider for MySecurityProvider {
    fn hash_secret(&self, data: &[u8]) -> std::result::Result<Vec<u8>, typelock::Error> {
        todo!("implement your own secret hashing logic here.")
    }
}
```

Additional traits are available for other policies:
- `DigestProvider` for `digest`
- `SignProvider` for `sign` / `verify_signature`
- `MacProvider` for `mac` / `verify_mac`

`typelock` **does not** implement cryptography itself; you always provide your own backend.

## Converting between models
`typelock` automatically provides the following model conversions:
1. OriginalModel -> LockedModel // call `.lock()`
2. LockedModel -> UnlockedModel // call `.unlock()`
3. UnlockedModel -> LockedModel // call `.lock()`

For one-way policies (`secret` and `digest`), the unlocked model still carries wrapped bytes (`Secret<T>` / `Digested<T>`) because the original plaintext cannot be reconstructed.

You are encouraged to always instantiate your own models starting from OriginalModel and never from LockedModel or UnlockedModel. This is because otherwise `typelock` is not able to guarantee that you actually secured your data correctly. 

```rust
use typelock::{Lockable, Unlockable};

let provider = MySecurityProvider;
let user = User {
    id: 1,
    email: "user@email".to_string(),
    password: "user-password".to_string(),
    user_data: UserData {
        first_name: "user".to_string(),
    },
};
let locked_user = user.lock(&provider);
let unlocked_user = locked_user.unlock(&provider).expect("implement error handling");
```

Calling `.lock()` and `.unlock()` move the previous model into the function call. This means that trying to access `user` after calling `.lock()` is not allowed. `typelock` also provides default implementations to call `.lock()` and `.unlock()` on collections of Vec<Model>.

**Warning:** you are discouraged from deriving `Clone` on your **original model** or any of the **generated models**. This is because doing the following could lead to ghost copies that stay in your program's memory, which could compromise data.

```rust
let user = User { ... }
let locked_user = user.clone().lock();
```

In cases you need to do so, please take a look at the [zeroize crate](https://crates.io/crates/zeroize) for example.

## Diesel Integration
When the `diesel` feature is enabled, `typelock` provides `FromSql` and `ToSql` implementations for `Encrypted<T>` and `Secret<T>`. This allows those locked fields to be stored directly as Diesel `Binary` columns.

```rust
#[derive(LockSchema)]
#[typelock(
    // unlocked...
    locked(
        name = UserLocked, 
        derives(Queryable, Selectable, Insertable),
        attributes(diesel(table_name = crate::schema::users))
    )
)]
pub struct User {
    pub id: i64,
    #[secure(policy(encrypt))]
    pub email: String,
}
```

Locked fields are stored as `Binary` in the database.

## Why use Typelock?
Without `typelock`, you typically end up writing code that looks like the following:

```rust
DecryptedUser {
    id: self.id,
    email: provider.decrypt(...),
    ...
}
```

This is verbose, easy to get wrong, and typically repeated among multiple models. `typelock` generates that boundary once, correctly.

## Use cases
`typelock` is useful when you need:
- Type-safe boundaries between plaintext and secured states (encrypted, secret-hashed, digested, signed, or MAC-tagged)
- Compile-time guarantees that sensitive data can't be accidentally used in the wrong state
- Automatic transitions between domain models and their storage representations
- To eliminate boilerplate for policy-based security transformations across multiple models
- To prevent accidentally serializing or logging sensitive data in plaintext form
- A strict separation between domain logic and persistence layer with security enforced at compile time

`typelock` complements your cryptography library by modeling security state transitions at the type level. It **does not** implement cryptography itself.

## License
This project is licensed under the MIT License.

This crate provides optional integration with [wincode](https://crates.io/crates/wincode) via the `wincode-codec` feature, and with [Diesel](https://diesel.rs/) via the `diesel` feature. Therefore the respective licenses of these dependencies apply.
