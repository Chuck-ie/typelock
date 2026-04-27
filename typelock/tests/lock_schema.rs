use typelock::{FromBytes, LockSchema, ToBytes};
use common::PolicyProvider;

mod common;

#[derive(LockSchema, Clone)]
#[typelock(
    unlocked(name = UserUnlocked, derives(Debug)), 
    locked(name = UserLocked, attributes(allow(dead_code)))
)]
struct User {
    pub id: i64,

    #[secure(policy(encrypt))]
    pub email: String,

    #[secure(policy(secret), rename = "password_hash")]
    pub password: String,

    #[secure(policy(encrypt))]
    pub user_data: UserData,
}

#[derive(Debug, Clone)]
struct UserData {
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

#[cfg(test)]
mod tests {
    use super::*;
    use typelock::{Lockable, Unlockable};

    #[test]
    fn test_conversion_between_models() {
        let provider = PolicyProvider;
        let user = User {
            id: 1,
            email: "user@email".to_string(),
            password: "user-password".to_string(),
            user_data: UserData {
                first_name: "user".to_string(),
            },
        };

        // We need to clone the user since both lock and unlock move the
        // original user model. Cloning sensitive data is generally discouraged
        // as it creates ghost copies in memory, that potentially compromise the
        // security of your data. I'm using clone here just for test purposes to
        // allow calling assert_eq!() to validate my crates implementation. Also
        // consider using the crate `zeroize` to remove sensitive data from memory.
        let locked_user = user.clone().lock(&provider).unwrap();
        let unlocked_user = user
            .clone()
            .lock(&provider)
            .unwrap()
            .unlock(&provider)
            .unwrap();

        assert_eq!(user.id, unlocked_user.id);
        assert_eq!(user.email, *unlocked_user.email);

        // Hashing is irreversable, hence both the locked and unlocked
        // user just store the hashed bytes which should be equal.
        assert_eq!(locked_user.password_hash, unlocked_user.password);

        assert_eq!(
            user.user_data.first_name,
            unlocked_user.user_data.first_name
        );
    }

    #[test]
    fn test_conversion_between_vec_models() {
        let provider = PolicyProvider;
        let user1 = User {
            id: 1,
            email: "user1@email".to_string(),
            password: "user1-password".to_string(),
            user_data: UserData {
                first_name: "user1".to_string(),
            },
        };

        let user2 = User {
            id: 2,
            email: "user2@email".to_string(),
            password: "user2-password".to_string(),
            user_data: UserData {
                first_name: "user2".to_string(),
            },
        };

        let users = vec![user1, user2];
        let locked_users = users.clone().lock(&provider).unwrap();
        let unlocked_users = locked_users.unlock(&provider).unwrap();

        assert_eq!(users.len(), unlocked_users.len());

        for (original, unlocked) in users.iter().zip(unlocked_users.iter()) {
            assert_eq!(original.id, unlocked.id);
            assert_eq!(original.email, *unlocked.email);
            assert_eq!(original.user_data.first_name, unlocked.user_data.first_name);
        }
    }

    #[test]
    fn test_derive_pass_through() {
        #[derive(LockSchema, Clone)]
        #[typelock(locked(name = LockedTest, derives(Debug)), unlocked(name = UnlockedTest, derives(Debug)))]
        #[allow(dead_code)]
        struct Test {
            id: i64,

            #[secure(policy(secret), rename = "password_hash")]
            password: String,
        }
    }

    #[test]
    fn test_attribute_pass_through() {
        #[derive(LockSchema, Clone)]
        #[typelock(locked(name = LockedTest, attributes(allow(dead_code))), unlocked(name = UnlockedTest, attributes(allow(dead_code))))]
        #[allow(dead_code)]
        struct Test {
            id: i64,

            #[secure(policy(secret), rename = "password_hash")]
            password: String,
        }
    }
}
