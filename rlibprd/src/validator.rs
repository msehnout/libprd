use crate::email2domain::*;
use crate::unbound::*;
use crate::{KeyInfo, Validity};
use data_encoding::BASE64;
use std::ptr;
use std::os::raw::{c_char, c_int};

pub struct Validator {
    unbound_context: *mut ub_ctx,
}

impl Drop for Validator {
    // add code here
    fn drop(&mut self) {
        unsafe {
            ub_ctx_delete(self.unbound_context);
        }
    }
}

impl Validator {
    pub fn try_new() -> Result<Validator, &'static str> {
        create_ub_ctx().map(|ctx| Validator{
            unbound_context: ctx,
        })
    }

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