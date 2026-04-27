use darling::ast::Fields;
use quote::{quote, quote_spanned};
use syn::spanned::Spanned;

use super::{
    helpers::{
        get_attributes, get_derives, get_field_rename, get_field_type, get_policy_providers,
    },
    LockSchemaReceiver, ModelKind, SecurePolicy, SecureReceiver,
};

pub fn gen_locked_model(
    input: &LockSchemaReceiver,
    fields: &Fields<SecureReceiver>,
) -> syn::Result<proc_macro2::TokenStream> {
    let vis = &input.vis;

    let Some(locked_model) = &input.locked else {
        return Ok(quote!());
    };

    let locked_model_name = &locked_model.name;
    let secure_fields = fields.iter().map(|f| {
        let f_vis = &f.vis;
        let f_name = get_field_rename(f);
        let f_ty = get_field_type(&f.ty, &f.policy, ModelKind::Locked);

        quote_spanned! { f.ident.span() =>
            #f_vis #f_name: #f_ty
        }
    });

    let locked_impl = gen_locked_model_impl(input, fields)?;
    let expanded_derives = get_derives(&input.locked);
    let expanded_attributes = get_attributes(&input.locked);

    Ok(quote! {
        #expanded_derives
        #expanded_attributes
        #vis struct #locked_model_name {
            #(#secure_fields,)*
        }

        #locked_impl
    })
}

fn gen_locked_model_impl(
    input: &LockSchemaReceiver,
    fields: &Fields<SecureReceiver>,
) -> syn::Result<proc_macro2::TokenStream> {
    let Some(locked) = &input.locked else {
        return Ok(quote!());
    };

    let Some(unlocked) = &input.unlocked else {
        return Ok(quote!());
    };

    let locked_model_name = &locked.name;
    let unlocked_model_name = &unlocked.name;

    let (field_names, transformations): (Vec<_>, Vec<_>) = fields
        .iter()
        .map(|f| {
            let f_ty = &f.ty;
            let f_name = f.ident.as_ref().unwrap();
            let f_renamed = get_field_rename(f);

            let transformation = match f.policy {
                SecurePolicy::Encrypt => quote_spanned! { f.ident.span() =>
                    let #f_name = ::typelock::CryptoProvider::decrypt(provider, &self.#f_renamed)?;
                    let #f_name = <#f_ty as ::typelock::FromBytes>::from_bytes(&#f_name)?;
                    let #f_name = ::typelock::Decrypted::new(#f_name);
                },
                SecurePolicy::Sign
                | SecurePolicy::Mac
                | SecurePolicy::None
                | SecurePolicy::Index
                | SecurePolicy::Secret
                | SecurePolicy::Digest => quote_spanned! { f.ident.span() =>
                    let #f_name = self.#f_renamed;
                },
                // SecurePolicy::Sign => quote_spanned! { f.ident.span() =>
                //     let #f_name = ::typelock::SignProvider::verify_signature(provider, &self.#f_renamed)?;
                //     let #f_name = <#f_ty as ::typelock::FromBytes>::from_bytes(&#f_name)?;
                //     let #f_name = ::typelock::Verified::new(#f_name);
                // },
                // SecurePolicy::Mac => quote_spanned! { f.ident.span() =>
                //     let #f_name = ::typelock::MacProvider::verify_mac(provider, &self.#f_renamed)?;
                //     let #f_name = <#f_ty as ::typelock::FromBytes>::from_bytes(&#f_name)?;
                //     let #f_name = ::typelock::Verified::new(#f_name);
                // },
            };

            (f_name, transformation)
        })
        .unzip();

    let required_providers = get_policy_providers(fields);

    Ok(quote_spanned! { input.ident.span() =>
        #[allow(unused_variables)]
        impl<P> ::typelock::Unlockable<P> for #locked_model_name
        where
            P: #(#required_providers)+*
        {
            type Output = #unlocked_model_name;

            #[inline]
            fn unlock(self, provider: &P) -> ::std::result::Result<Self::Output, ::typelock::Error> {
                #(#transformations)*

                ::std::result::Result::Ok(#unlocked_model_name {
                    #(#field_names,)*
                })
            }
        }
    })
}
