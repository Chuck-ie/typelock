use darling::FromDeriveInput;
use syn::{parse_macro_input, DeriveInput};

use crate::{
    lock_schema::LockSchemaReceiver,
    wincode_codec::{FromBytesReceiver, ToBytesReceiver},
};

mod lock_schema;
mod wincode_codec;

#[proc_macro_derive(LockSchema, attributes(typelock, secure))]
pub fn derive_lock_schema(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let input = match LockSchemaReceiver::from_derive_input(&input) {
        Ok(val) => val,
        Err(e) => return e.write_errors().into(),
    };

    lock_schema::generate(&input)
        .unwrap_or_else(|e| e.into_compile_error())
        .into()
}

#[proc_macro_derive(ToBytes)]
pub fn derive_to_bytes(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let input = match ToBytesReceiver::from_derive_input(&input) {
        Ok(val) => val,
        Err(e) => return e.write_errors().into(),
    };

    wincode_codec::generate_to_bytes(&input)
        .unwrap_or_else(|e| e.into_compile_error())
        .into()
}

#[proc_macro_derive(FromBytes)]
pub fn derive_from_bytes(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let input = match FromBytesReceiver::from_derive_input(&input) {
        Ok(val) => val,
        Err(e) => return e.write_errors().into(),
    };

    wincode_codec::generate_from_bytes(&input)
        .unwrap_or_else(|e| e.into_compile_error())
        .into()
}
