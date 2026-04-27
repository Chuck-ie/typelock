use darling::{
    ast::Data,
    util::{Ignored, PathList},
    FromDeriveInput, FromField, FromMeta,
};
use quote::quote;

mod codegen_locked;
mod codegen_schema;
mod codegen_unlocked;
mod helpers;

use codegen_locked::gen_locked_model;
use codegen_schema::gen_schema_model_impl;
use codegen_unlocked::gen_unlocked_model;

// TODO: add verify step in addition to a unlock step
// TODO: possibly add per field verify generation
// TODO: add joined version i.e. Locked.unlock_verify(...)
//
// TODO: possibly add stacked policy for indexed fields to allow simplifying this:
// let owner_account = InsertUserAccount {
//     email_index: self.email.clone(),
//     email: self.email,
//     password: self.password,
// }
// .lock(vault)?;
//
// to something like this:
//
// pub struct User {
//    version 1:
//    #[secure(policy(encrypt, index(rename = "email_index")))]
//
//    version 2:
//    #[secure(policy(encrypt))]
//    #[secure(policy(index(rename = "email_index")))]
//    pub email: String
// }
//
// which would then generaate the email_index field for the generated structs only

#[derive(Debug, FromDeriveInput)]
#[darling(
    attributes(typelock),
    supports(struct_named, enum_any),
    forward_attrs(allow)
)]
pub struct LockSchemaReceiver {
    pub ident: syn::Ident,
    pub vis: syn::Visibility,
    pub data: Data<Ignored, SecureReceiver>,

    #[darling(default)]
    pub unlocked: Option<ModelSettings>,

    #[darling(default)]
    pub locked: Option<ModelSettings>,
}

#[derive(Debug, FromMeta)]
pub struct ModelSettings {
    pub name: syn::Ident,

    #[darling(default)]
    pub derives: Option<PathList>,

    #[darling(default)]
    pub(crate) attributes: Option<ForwardAttributes>,
}

#[derive(Debug)]
pub(crate) struct ForwardAttributes(pub Vec<proc_macro2::TokenStream>);

impl FromMeta for ForwardAttributes {
    fn from_list(items: &[darling::ast::NestedMeta]) -> darling::Result<Self> {
        let mapped_items = items
            .iter()
            .map(|i| {
                quote! { #i }
            })
            .collect();

        Ok(ForwardAttributes(mapped_items))
    }
}

#[derive(Debug, FromField)]
#[darling(attributes(secure))]
pub struct SecureReceiver {
    pub ident: Option<syn::Ident>,
    pub vis: syn::Visibility,
    pub ty: syn::Type,

    #[darling(default)]
    pub policy: SecurePolicy,

    #[darling(default)]
    pub rename: Option<String>,
}

#[derive(Debug, Default, FromMeta, PartialEq, Eq, Hash)]
pub enum SecurePolicy {
    #[default]
    #[darling(word)]
    None,
    Index,
    Encrypt,
    Secret,
    Digest,
    Sign,
    Mac,
}

pub enum ModelKind {
    Unlocked,
    Locked,
}

pub fn generate(input: &LockSchemaReceiver) -> syn::Result<proc_macro2::TokenStream> {
    let fields = match &input.data {
        Data::Struct(fields) => fields,
        _ => {
            return Err(syn::Error::new_spanned(
                &input.ident,
                "Only named structs are supported",
            ));
        }
    };

    let schema_impl = gen_schema_model_impl(input, fields)?;
    let unlocked_model = gen_unlocked_model(input, fields)?;
    let locked_model = gen_locked_model(input, fields)?;
    let output = quote! {
        #schema_impl
        #unlocked_model
        #locked_model
    };

    Ok(output)
}
