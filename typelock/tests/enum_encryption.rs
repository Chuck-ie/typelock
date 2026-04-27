#![cfg(feature = "wincode-codec")]
use crate::common::PolicyProvider;
use typelock::{FromBytes, LockSchema, Lockable, ToBytes, Unlockable};

mod common;

#[derive(LockSchema, Clone)]
#[typelock(locked(name = LockedUser), unlocked(name = UnlockedUser))]
struct User {
    #[secure(policy(encrypt))]
    user_data: UserDataEnvelope,
}

#[derive(Clone, ToBytes, FromBytes, wincode::SchemaRead, wincode::SchemaWrite)]
enum UserDataEnvelope {
    V1(UserData),
}

#[derive(Clone, wincode::SchemaRead, wincode::SchemaWrite)]
struct UserData {
    first_name: String,
    last_name: String,
}

#[test]
fn test_enum_encryption() {
    let provider = PolicyProvider;
    let user = User {
        user_data: UserDataEnvelope::V1(UserData {
            first_name: "first_name".to_string(),
            last_name: "last_name".to_string(),
        }),
    };

    let locked_user = user.clone().lock(&provider).unwrap();
    let unlocked_user = locked_user.unlock(&provider).unwrap();

    let (UserDataEnvelope::V1(original), UserDataEnvelope::V1(decrypted)) =
        (&user.user_data, &*unlocked_user.user_data);

    assert_eq!(original.first_name, decrypted.first_name);
    assert_eq!(original.last_name, decrypted.last_name);
}
