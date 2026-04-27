use std::string::FromUtf8Error;

// TODO: rewrite how errors are generated. Its probably
// better if the user can provide his own error types
#[derive(Debug)]
pub enum Error {
    ByteConversion(String),
    Wincode(String),
    Indexing(String),
    Encryption(String),
    Decryption(String),
    Hashing(String),
    Signing(String),
    SignatureVerification(String),
    Mac(String),
    MacVerification(String),
    Digest(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ByteConversion(msg) => write!(f, "Byte conversion error: {msg}"),
            Error::Wincode(msg) => write!(f, "Wincode codec error: {msg}"),
            Error::Indexing(msg) => write!(f, "Indexing failed: {msg}"),
            Error::Encryption(msg) => write!(f, "Encryption failed: {msg}"),
            Error::Decryption(msg) => write!(f, "Decryption failed: {msg}"),
            Error::Hashing(msg) => write!(f, "Hashing error: {msg}"),
            Error::Signing(msg) => write!(f, "Signing failed: {msg}"),
            Error::SignatureVerification(msg) => write!(f, "Signature verification failed: {msg}"),
            Error::Mac(msg) => write!(f, "MAC tagging failed: {msg}"),
            Error::MacVerification(msg) => write!(f, "MAC verification failed: {msg}"),
            Error::Digest(msg) => write!(f, "Digest failed: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<FromUtf8Error> for Error {
    fn from(value: FromUtf8Error) -> Self {
        Error::ByteConversion(value.to_string())
    }
}
