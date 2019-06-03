use crate::unbound::*;
use std::ptr;

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
    pub fn try_new() -> Option<Validator> {
        unsafe {
            create_ub_ctx().map(|ctx| Validator{
                unbound_context: ctx,
            })
        }
    }

    pub fn resolve(&mut self, domain: &str) {
        let mut result: *mut ub_result = ptr::null_mut();
        let domain = String::from(domain) + "\0";
        unsafe {
            let retval = ub_resolve(self.unbound_context, domain.as_ptr() as *const i8, 61, 1, &mut result);

            if retval != 0 {
                eprintln!("Failed to resolve host");
                return;
            }

            if (*result).havedata == 0 {
                eprintln!("The result does not contain data");
            }

            if (*result).nxdomain != 0 {
                eprintln!("NXDOMAIN");
            }

            if (*result).secure != 0 {
                eprintln!("SECURE");
            } else {
                eprintln!("UNSECURE");
            }

            println!("end!");
        }
    }
}