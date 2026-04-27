use darling::ast::Fields;
use quote::{quote, quote_spanned};
use syn::spanned::Spanned;

use super::{
    helpers::{
        get_attributes, get_derives, get_field_rename, get_field_type, get_policy_providers,
    },
    LockSchemaReceiver, ModelKind, SecurePolicy, SecureReceiver,
};

pub fn gen_unlocked_model(
    input: &LockSchemaReceiver,
    fields: &Fields<SecureReceiver>,
) -> syn::Result<proc_macro2::TokenStream> {
    let vis = &input.vis;

    let Some(unlocked) = &input.unlocked else {
        return Ok(quote!());
    };

    let unlocked_model_name = &unlocked.name;
    let unlocked_fields = fields.iter().map(|f| {
        let f_vis = &f.vis;
        let f_name = f.ident.as_ref().unwrap();
        let f_ty = get_field_type(&f.ty, &f.policy, ModelKind::Unlocked);

        quote_spanned! { f.ident.span() =>
            #f_vis #f_name: #f_ty
        }
    });

    let unlocked_impl = gen_unlocked_model_impl(input, fields)?;
    let expanded_derives = get_derives(&input.unlocked);
    let expanded_attributes = get_attributes(&input.unlocked);

    Ok(quote! {
            #expanded_derives
            #expanded_attributes
            #vis struct #unlocked_model_name {
            #(#unlocked_fields,)*
        }

        #unlocked_impl
    })
}

fn gen_unlocked_model_impl(
    input: &LockSchemaReceiver,
    fields: &Fields<SecureReceiver>,
) -> syn::Result<proc_macro2::TokenStream> {
    if input.unlocked.is_none() {
        return Ok(quote!());
    }

    if input.unlocked.is_some() && input.locked.is_none() {
        return Err(syn::Error::new(
            input.ident.span(),
            "An unlocked model requires a locked model. \
            Add `locked = ...` to the LockSchema derive macro \
            and take a look at the section `## Converting \
            between models` in the readme",
        ));
    }

    let unlocked_model_name = &input.unlocked.as_ref().unwrap().name;
    let locked_model_name = &input.locked.as_ref().unwrap().name;

    let (field_names, transformations): (Vec<_>, Vec<_>) = fields
        .iter()
        .map(|f| {
            let f_name = f.ident.as_ref().unwrap();
            let f_renamed = get_field_rename(f);

            let transformation = match f.policy {
                SecurePolicy::None => quote_spanned! { f.ident.span() =>
                    let #f_renamed = self.#f_name;
                },
                SecurePolicy::Encrypt => quote_spanned! { f.ident.span() =>
                    let #f_renamed = ::typelock::ToBytes::to_bytes(&self.#f_name)?;
                    let #f_renamed = ::typelock::CryptoProvider::encrypt(provider, &#f_renamed)?;
                    let #f_renamed = ::typelock::Encrypted::new(#f_renamed);
                },
                SecurePolicy::Sign
                | SecurePolicy::Mac
                | SecurePolicy::Index
                | SecurePolicy::Secret
                | SecurePolicy::Digest => {
                    quote_spanned! { f.ident.span() =>
                        let #f_renamed = self.#f_name;
                    }
                } // SecurePolicy::Sign => quote_spanned! { f.ident.span() =>
                  //     let #f_renamed = ::typelock::ToBytes::to_bytes(&self.#f_name)?;
                  //     let #f_renamed = ::typelock::SignProvider::sign(provider, &#f_renamed)?;
                  //     let #f_renamed = ::typelock::Signed::new(#f_renamed);
                  // },
                  // SecurePolicy::Mac => quote_spanned! { f.ident.span() =>
                  //     let #f_renamed = ::typelock::ToBytes::to_bytes(&self.#f_name)?;
                  //     let #f_renamed = ::typelock::MacProvider::tag(provider, &#f_renamed)?;
                  //     let #f_renamed = ::typelock::Tagged::new(#f_renamed);
                  // },
            };

            (f_renamed, transformation)
        })
        .unzip();

    let required_providers = get_policy_providers(fields);

    Ok(quote_spanned! { input.ident.span() =>
        #[allow(unused_variables)]
        impl<P> ::typelock::Lockable<P> for #unlocked_model_name
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
