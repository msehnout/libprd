use crate::email2domain::*;
use crate::unbound::*;
use crate::{KeyInfo, Validity};
use data_encoding::BASE64;
use std::ptr;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int};

/// Helper function to get errors from unbound
unsafe fn get_ub_strerror(err: c_int) -> String {
    CStr::from_ptr(ub_strerror(err))
        .to_string_lossy()
        .into_owned()
}

/// Helper function to create preconfigured unbound context.
/// 
/// Make any changes regarding the configuration here. e.g. trust anchors, TLS forwarding ...
pub(crate) fn create_ub_ctx() -> Result<*mut ub_ctx, &'static str> {
    let ctx;
    unsafe {
        ctx = ub_ctx_create();

        if ctx.is_null() {
            return Err("Failed to create context");
        }

        if ub_ctx_resolvconf(ctx, ptr::null()) != 0 {
            ub_ctx_delete(ctx);
            return Err("Failed to load resolv.conf");
        }

        let hosts = "/etc/hosts\0";
        let retval = ub_ctx_hosts(ctx, hosts.as_ptr() as *const i8);
        if retval != 0 {
            eprintln!("Failed to load hosts: {}", get_ub_strerror(retval));
            ub_ctx_delete(ctx);
            return Err("Failed to load hosts");
        }

        let ta_file = "/etc/trusted-key.key\0";
        let retval = ub_ctx_add_ta_file(ctx, ta_file.as_ptr() as *const i8);
        if retval != 0 {
            eprintln!("Failed to load ta_file: {}", get_ub_strerror(retval));
            ub_ctx_delete(ctx);
            return Err("Failed to load ta_file");
        }
    }
    eprintln!("Successfully created unbound context");
    Ok(ctx)
}

/// The main object responsible for validation. Provided as an opaque struct for the C API.
pub struct Validator {
    unbound_context: *mut ub_ctx,
}

impl Drop for Validator {
    fn drop(&mut self) {
        // We need to explicitly call Unbound API here.
        unsafe {
            ub_ctx_delete(self.unbound_context);
        }
    }
}

impl Validator {
    /// Try to create new Validator object.
    pub fn try_new() -> Result<Validator, &'static str> {
        create_ub_ctx().map(|ctx| Validator{
            unbound_context: ctx,
        })
    }

    /// Method for GPG key validation.
    pub fn validate(&mut self, key_info: KeyInfo) -> Validity {
        let mut result: *mut ub_result = ptr::null_mut();
        let domain = match email2domain(&key_info.email) {
            Ok(d) => d,
            Err(_) => return Validity::ERROR,
        };
        let domain = domain + "\0";
        unsafe {
            let retval = ub_resolve(self.unbound_context,
                                    domain.as_ptr() as *const i8,
                                    61, // OPENPGPKEY RR
                                    1,  // IN class
                                    &mut result);

            if retval != 0 {
                return Validity::ERROR;
            }
            if (*result).bogus != 0 {
                return Validity::BOGUS_RESULT;
            }
            if (*result).secure == 0 {
                return Validity::RESULT_NOT_SECURE;
            }
            if (*result).nxdomain != 0 {
                return Validity::PROVEN_NONEXISTENCE;
            }
            if (*result).havedata == 0 {
                return Validity::ERROR;
            } else {
                let key_from_dns: *const c_char = *((*result).data.offset(0));
                let key_length: usize = *((*result).len.offset(0)) as usize;

                let reinterpreted_ptr = key_from_dns as *const u8;
                let mut key_vector = Vec::with_capacity(key_length);
                key_vector.set_len(key_length);
                ptr::copy(reinterpreted_ptr, key_vector.as_mut_ptr(), key_length);

                let key_str = BASE64.encode(&key_vector);
                println!("KEY: {}, len: {}", key_str, key_length);
                if key_str == key_info.b64_key {
                    return Validity::VALID;
                } else {
                    return Validity::REVOKED;
                }
            }
        }
    }
}