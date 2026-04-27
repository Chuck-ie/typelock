use darling::ast::Fields;
use quote::{quote, quote_spanned};
use syn::spanned::Spanned;

use super::{
    helpers::{get_field_rename, get_policy_providers},
    LockSchemaReceiver, SecurePolicy, SecureReceiver,
};

pub fn gen_schema_model_impl(
    input: &LockSchemaReceiver,
    fields: &Fields<SecureReceiver>,
) -> syn::Result<proc_macro2::TokenStream> {
    let Some(locked) = &input.locked else {
        return Ok(quote!());
    };

    let schema_model_name = &input.ident;
    let locked_model_name = &locked.name;

    let (field_names, transformations): (Vec<_>, Vec<_>) = fields
        .iter()
        .map(|f| {
            let f_name = f.ident.as_ref().unwrap();
            let f_renamed = get_field_rename(f);

            let transformation = match f.policy {
                SecurePolicy::None => quote_spanned! { f.ident.span() =>
                    let #f_renamed = self.#f_name;
                },
                SecurePolicy::Index => quote_spanned! { f.ident.span() => 
                    let #f_renamed = ::typelock::ToBytes::to_bytes(&self.#f_name)?;
                    let #f_renamed = ::typelock::IndexProvider::index(provider, &#f_renamed)?;
                    let #f_renamed = ::typelock::Indexed::new(#f_renamed);
                },
                SecurePolicy::Encrypt => quote_spanned! { f.ident.span() =>
                    let #f_renamed = ::typelock::ToBytes::to_bytes(&self.#f_name)?;
                    let #f_renamed = ::typelock::CryptoProvider::encrypt(provider, &#f_renamed)?;
                    let #f_renamed = ::typelock::Encrypted::new(#f_renamed);
                },
                SecurePolicy::Secret => quote_spanned! { f.ident.span() =>
                    let #f_renamed = ::typelock::ToBytes::to_bytes(&self.#f_name)?;
                    let #f_renamed = ::typelock::SecretProvider::hash_secret(provider, &#f_renamed)?;
                    let #f_renamed = ::typelock::Secret::new(#f_renamed);
                },
                SecurePolicy::Digest => quote_spanned! { f.ident.span() =>
                    let #f_renamed = ::typelock::ToBytes::to_bytes(&self.#f_name)?;
                    let #f_renamed = ::typelock::DigestProvider::digest(provider, &#f_renamed)?;
                    let #f_renamed = ::typelock::Digested::new(#f_renamed);
                },
                SecurePolicy::Sign => quote_spanned! { f.ident.span() =>
                    let #f_renamed = ::typelock::ToBytes::to_bytes(&self.#f_name)?;
                    let #f_renamed = ::typelock::SignProvider::sign(provider, &#f_renamed)?;
                    let #f_renamed = ::typelock::Signed::new(#f_renamed);
                },
                SecurePolicy::Mac => quote_spanned! { f.ident.span() =>
                    let #f_renamed = ::typelock::ToBytes::to_bytes(&self.#f_name)?;
                    let #f_renamed = ::typelock::MacProvider::tag(provider, &#f_renamed)?;
                    let #f_renamed = ::typelock::Tagged::new(#f_renamed);
                },
            };

            (f_renamed, transformation)
        })
        .unzip();

    let required_providers = get_policy_providers(fields);

    Ok(quote_spanned! { input.ident.span() =>
        #[allow(unused_variables)]
        impl<P> ::typelock::Lockable<P> for #schema_model_name
        where
            P: #(#required_providers)+*
        {
            type Output = #locked_model_name;

            #[inline]
            fn lock(self, provider: &P) -> ::std::result::Result<Self::Output, ::typelock::Error> {
                #(#transformations)*

                ::std::result::Result::Ok(#locked_model_name {
                    #(#field_names,)*
                })
            }
        }
    })
}
