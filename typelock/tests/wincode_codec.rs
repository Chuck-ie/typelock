#![cfg(feature = "wincode-codec")]
use common::PolicyProvider;
use typelock::{FromBytes, LockSchema, ToBytes};

mod common;

#[derive(LockSchema, Clone)]
#[typelock(unlocked(name = UserUnlocked, derives(Debug)), locked(name = UserLocked))]
struct User {
    #[secure(policy(encrypt))]
    auto_codec_data: AutoCodecData,
}

#[derive(Debug, Default, Clone, ToBytes, FromBytes, wincode::SchemaRead, wincode::SchemaWrite)]
struct AutoCodecData {
    last_name: String,
    favorite_number: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use typelock::{Lockable, Unlockable};

    #[test]
    fn test_to_and_from_bytes() {
        let provider = PolicyProvider;
        let user = User {
            auto_codec_data: AutoCodecData {
                last_name: "last_name".to_string(),
                favorite_number: 1,
            },
        };

        let locked_user = user.clone().lock(&provider).unwrap();
        assert!(locked_user.auto_codec_data.starts_with(b"encrypted:"));
        let unlocked_user = locked_user.unlock(&provider).unwrap();

        assert_eq!(
            user.auto_codec_data.last_name,
            unlocked_user.auto_codec_data.last_name
        );
        assert_eq!(
            user.auto_codec_data.favorite_number,
            unlocked_user.auto_codec_data.favorite_number
        );
    }
}
