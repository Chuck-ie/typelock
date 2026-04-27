use common::PolicyProvider;
use typelock::{LockSchema, Lockable, Unlockable};

mod common;

// TODO: add better testing that adds verification which
// should be a different step to unlocking a model

#[derive(LockSchema, Clone)]
#[typelock(unlocked(name = PolicyUnlocked), locked(name = PolicyLocked))]
struct PolicyRecord {
    #[secure(policy(encrypt), rename = "encrypted_blob")]
    encrypted_value: String,

    #[secure(policy(secret), rename = "secret_blob")]
    secret_value: String,

    #[secure(policy(digest), rename = "digest_blob")]
    digest_value: String,

    #[secure(policy(sign), rename = "signed_blob")]
    signed_value: String,

    #[secure(policy(mac), rename = "mac_blob")]
    mac_value: String,
}

fn sample_record() -> PolicyRecord {
    PolicyRecord {
        encrypted_value: "plaintext".to_string(),
        secret_value: "secret-input".to_string(),
        digest_value: "digest-input".to_string(),
        signed_value: "signed".to_string(),
        mac_value: "tagged".to_string(),
    }
}

#[test]
fn test_encrypt_provider_roundtrip() {
    let provider = PolicyProvider;
    let source = sample_record();

    let locked = source.clone().lock(&provider).unwrap();
    assert_eq!(&*locked.encrypted_blob, b"encrypted:plaintext");

    let unlocked = locked.unlock(&provider).unwrap();
    assert_eq!(source.encrypted_value, unlocked.encrypted_value.as_str());
}

#[test]
fn test_secret_provider_lock_and_unlock() {
    let provider = PolicyProvider;
    let source = sample_record();

    let locked = source.clone().lock(&provider).unwrap();
    assert_eq!(&*locked.secret_blob, b"secret:secret-input");

    let unlocked = locked.unlock(&provider).unwrap();
    assert_eq!(
        unlocked.secret_value,
        source.lock(&provider).unwrap().secret_blob
    );
}

#[test]
fn test_digest_provider_lock_and_unlock() {
    let provider = PolicyProvider;
    let source = sample_record();

    let locked = source.clone().lock(&provider).unwrap();
    assert_eq!(&*locked.digest_blob, b"digest:digest-input");

    let unlocked = locked.unlock(&provider).unwrap();
    assert_eq!(
        unlocked.digest_value,
        source.lock(&provider).unwrap().digest_blob
    );
}

#[test]
fn test_sign_provider_roundtrip() {
    let provider = PolicyProvider;
    let source = sample_record();

    let locked = source.clone().lock(&provider).unwrap();
    assert_eq!(&*locked.signed_blob, b"sig:signed");

    // let unlocked = locked.unlock(&provider).unwrap();
    // assert_eq!(source.signed_value, unlocked.signed_value.as_str());
}

#[test]
fn test_mac_provider_roundtrip() {
    let provider = PolicyProvider;
    let source = sample_record();

    let locked = source.clone().lock(&provider).unwrap();
    assert_eq!(&*locked.mac_blob, b"mac:tagged");

    // let unlocked = locked.unlock(&provider).unwrap();
    // assert_eq!(source.mac_value, unlocked.mac_value.as_str());
}
