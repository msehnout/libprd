use crate::unbound::*;
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

    pub fn resolve(&mut self, domain: &str) {
        let mut result: *mut ub_result = ptr::null_mut();
        let domain = String::from(domain) + "\0";
        unsafe {
            let retval = ub_resolve(self.unbound_context,
                                    domain.as_ptr() as *const i8,
                                    61, // OPENPGPKEY RR
                                    1,  // IN class
                                    &mut result);

            if retval != 0 {
                eprintln!("Failed to resolve host");
                return;
            }

            if (*result).nxdomain != 0 {
                eprintln!("NXDOMAIN");
                return;
            }

            if (*result).secure != 0 {
                eprintln!("SECURE");
            } else {
                eprintln!("UNSECURE");
            }

            if (*result).havedata == 0 {
                eprintln!("The result does not contain data");
            } else {
                unsafe fn from_buf_raw(ptr: *const c_char, elts: usize) -> Vec<u8> {
                    let reinterpreted_ptr = ptr as *const u8;
                    let mut dst = Vec::with_capacity(elts);
                    dst.set_len(elts);
                    ptr::copy(reinterpreted_ptr, dst.as_mut_ptr(), elts);
                    dst
                }

                let key_from_dns: *const c_char = *((*result).data.offset(0));
                let key_length: usize = *((*result).len.offset(0)) as usize;
                let mut key_vector = from_buf_raw(key_from_dns, key_length);
                let key_str = BASE64.encode(&key_vector);
                println!("KEY: {}, len: {}", key_str, key_length);
            }

            println!("end!");
        }
    }
}