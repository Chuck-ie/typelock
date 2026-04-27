use darling::FromDeriveInput;
use quote::quote_spanned;

#[derive(Debug, FromDeriveInput)]
pub struct ToBytesReceiver {
    pub ident: syn::Ident,
}

#[derive(Debug, FromDeriveInput)]
pub struct FromBytesReceiver {
    ident: syn::Ident,
}

pub fn generate_to_bytes(input: &ToBytesReceiver) -> syn::Result<proc_macro2::TokenStream> {
    let ident = &input.ident;

    Ok(quote_spanned! { input.ident.span() =>
        impl ::typelock::ToBytes for #ident
        {
            fn to_bytes(&self) -> ::std::result::Result<::std::vec::Vec<u8>, ::typelock::Error> {
                ::typelock::wincode::serialize(self).map_err(|e| ::typelock::Error::Wincode(e.to_string()))
            }
        }
    })
}

pub fn generate_from_bytes(input: &FromBytesReceiver) -> syn::Result<proc_macro2::TokenStream> {
    let ident = &input.ident;

    Ok(quote_spanned! { input.ident.span() =>
        impl ::typelock::FromBytes for #ident
        {
            fn from_bytes(bytes: &[u8]) -> ::std::result::Result<Self, ::typelock::Error> {
                ::typelock::wincode::deserialize(bytes).map_err(|e| ::typelock::Error::Wincode(e.to_string()))
            }
        }
    })
}
