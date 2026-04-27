use darling::ast::Fields;
use proc_macro2::Span;
use quote::quote;
use std::collections::HashSet;
use syn::Ident;

use super::{ModelKind, ModelSettings, SecurePolicy, SecureReceiver};

pub fn get_field_rename(f: &SecureReceiver) -> Ident {
    match &f.rename {
        Some(new_name) => Ident::new(new_name, Span::call_site()),
        None => f.ident.clone().unwrap(),
    }
}

pub fn get_field_type(
    base_ty: &syn::Type,
    policy: &SecurePolicy,
    kind: ModelKind,
) -> proc_macro2::TokenStream {
    match (kind, policy) {
        (_, SecurePolicy::None) => quote!(#base_ty),
        (_, SecurePolicy::Index) => quote!(::typelock::Indexed<#base_ty>),

        // Encrypt
        (ModelKind::Unlocked, SecurePolicy::Encrypt) => quote!(::typelock::Decrypted<#base_ty>),
        (ModelKind::Locked, SecurePolicy::Encrypt) => quote!(::typelock::Encrypted<#base_ty>),

        (_, SecurePolicy::Secret) => quote!(::typelock::Secret<#base_ty>),
        (_, SecurePolicy::Digest) => quote!(::typelock::Digested<#base_ty>),
        (_, SecurePolicy::Sign) => quote!(::typelock::Signed<#base_ty>),
        (_, SecurePolicy::Mac) => quote!(::typelock::Tagged<#base_ty>),
    }
}

pub fn get_policy_providers(fields: &Fields<SecureReceiver>) -> Vec<proc_macro2::TokenStream> {
    let policies: HashSet<_> = fields
        .iter()
        .map(|f| &f.policy)
        .filter(|&p| *p != SecurePolicy::None)
        .collect();

    policies
        .iter()
        .map(|&p| match p {
            SecurePolicy::None => {
                unreachable!("None policies should've be filtered out. This is a Bug!")
            }
            SecurePolicy::Index => quote!(::typelock::IndexProvider),
            SecurePolicy::Encrypt => quote!(::typelock::CryptoProvider),
            SecurePolicy::Secret => quote!(::typelock::SecretProvider),
            SecurePolicy::Digest => quote!(::typelock::DigestProvider),
            SecurePolicy::Sign => quote!(::typelock::SignProvider),
            SecurePolicy::Mac => quote!(::typelock::MacProvider),
        })
        .collect()
}

pub fn get_derives(settings: &Option<ModelSettings>) -> proc_macro2::TokenStream {
    let Some(settings) = settings else {
        return quote!();
    };
    let Some(derives) = &settings.derives else {
        return quote!();
    };
    quote!(#[derive(#(#derives),*)])
}

pub fn get_attributes(settings: &Option<ModelSettings>) -> proc_macro2::TokenStream {
    let Some(settings) = settings else {
        return quote!();
    };
    let Some(attributes) = &settings.attributes else {
        return quote!();
    };

    let attributes = &attributes.0;
    quote!(#(#[#attributes])*)
}
