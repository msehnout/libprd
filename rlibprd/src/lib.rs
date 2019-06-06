//! # rlibprd
//! ## a library to verify PGP keys using DNSSEC
//! 
//! `rlibprd` exports C API for public usage and uses `libunbound` and `openssl`
//! to verify the keys.

mod unbound;
mod validator;
mod email2domain;
#[cfg(test)]
mod tests;

use std::ffi::CStr;
use std::mem;
use std::os::raw::c_char;
use validator::Validator;

/// PGP key parsed into a pair of strings (email, b64 encoded key)
pub struct KeyInfo {
    pub email: String,
    pub b64_key: String,
}

/// Return value from the process of key validation
#[derive(Debug, PartialEq)]
#[repr(C)]
#[allow(non_camel_case_types)]
pub enum Validity {
    VALID = 1,
    REVOKED = 2,
    PROVEN_NONEXISTENCE = 3,
    RESULT_NOT_SECURE = 4,
    BOGUS_RESULT = 5,
    ERROR = 9,
}

/// PGP key parsed into a pair of C strings (email, b64 encoded key)
#[repr(C)]
pub struct KeyInfoC {
    pub email: *const c_char,
    pub b64_key: *const c_char,
}

/// Create a validator context, returns a pointer to a heap allocated structure
#[no_mangle]
pub extern "C" fn prd_validator_create() -> *mut Validator {
    let validator = Box::new(Validator::try_new().unwrap());
    Box::into_raw(validator)
}

/// Validate a GPG key passed to the function as the KeyInfoC structure
#[no_mangle]
pub unsafe extern "C" fn prd_validator_validate(validator: *mut Validator, key_info: *const KeyInfoC) -> Validity {
    let mut validator = Box::from_raw(validator);
    let ki = KeyInfo {
        email: CStr::from_ptr((*key_info).email).to_string_lossy().into_owned(),
        b64_key: CStr::from_ptr((*key_info).b64_key).to_string_lossy().into_owned(),
    };
    let validity = validator.validate(ki);
    mem::forget(validator);
    validity
}

/// Destroy the context
#[no_mangle]
pub unsafe extern "C" fn prd_validator_destroy(ptr: *mut Validator) {
    Box::from_raw(ptr);
}