use std::ffi::CStr;
use std::ptr;
use std::os::raw::{c_char, c_int, c_void};

#[repr(C)]
pub struct ub_result {
	/** The original question, name text string. */
    //char* qname;
	pub qname: *const c_char,
	/** the type asked for */
    //int qtype;
	pub qtype: c_int,
	/** the class asked for */
    //int qclass;
	pub qclass: c_int,

	/** 
	 * a list of network order DNS rdata items, terminated with a 
	 * NULL pointer, so that data[0] is the first result entry,
	 * data[1] the second, and the last entry is NULL. 
	 * If there was no data, data[0] is NULL.
	 */
	//char** data;
    pub data: *const *const c_char,

	/** the length in bytes of the data items, len[i] for data[i] */
	//int* len;
    pub len: c_int,

	/** 
	 * canonical name for the result (the final cname). 
	 * zero terminated string.
	 * May be NULL if no canonical name exists.
	 */
	//char* canonname;
    pub canonname: *const c_char,

	/**
	 * DNS RCODE for the result. May contain additional error code if
	 * there was no data due to an error. 0 (NOERROR) if okay.
	 */
	//int rcode;
    pub rcode: c_int,

	/**
	 * The DNS answer packet. Network formatted. Can contain DNSSEC types.
	 */
	//void* answer_packet;
    pub answer_packet: *const c_void,
	/** length of the answer packet in octets. */
	//int answer_len;
    pub answer_len: c_int,

	/**
	 * If there is any data, this is true.
	 * If false, there was no data (nxdomain may be true, rcode can be set).
	 */
	//int havedata;
    pub havedata: c_int,

	/** 
	 * If there was no data, and the domain did not exist, this is true.
	 * If it is false, and there was no data, then the domain name 
	 * is purported to exist, but the requested data type is not available.
	 */
	//int nxdomain;
    pub nxdomain: c_int,

	/**
	 * True, if the result is validated securely.
	 * False, if validation failed or domain queried has no security info.
	 *
	 * It is possible to get a result with no data (havedata is false),
	 * and secure is true. This means that the non-existence of the data
	 * was cryptographically proven (with signatures).
	 */
	//int secure;
    pub secure: c_int,

	/** 
	 * If the result was not secure (secure==0), and this result is due 
	 * to a security failure, bogus is true.
	 * This means the data has been actively tampered with, signatures
	 * failed, expected signatures were not present, timestamps on 
	 * signatures were out of date and so on.
	 *
	 * If !secure and !bogus, this can happen if the data is not secure 
	 * because security is disabled for that domain name. 
	 * This means the data is from a domain where data is not signed.
	 */
	//int bogus;
    pub bogus: c_int,
	
	/**
	 * If the result is bogus this contains a string (zero terminated)
	 * that describes the failure.  There may be other errors as well
	 * as the one described, the description may not be perfectly accurate.
	 * Is NULL if the result is not bogus.
	 */
	//char* why_bogus;
    pub why_bogus: *const c_char,

	/**
	 * If the query or one of its subqueries was ratelimited. Useful if
	 * ratelimiting is enabled and answer is SERVFAIL.
	 */
	//int was_ratelimited;
    pub was_ratelimited: c_int,

	/**
	 * TTL for the result, in seconds.  If the security is bogus, then
	 * you also cannot trust this value.
	 */
    //int ttl;
    pub ttl: c_int,
}

#[repr(C)]
pub struct ub_ctx {
    private: [u8; 0]
}

#[link(name = "unbound")]
extern "C" {
    pub fn ub_ctx_create() -> *mut ub_ctx;
    pub fn ub_ctx_delete(ctx: *mut ub_ctx);
    pub fn ub_ctx_resolvconf(ctx: *mut ub_ctx, fname: *const c_char) -> c_int;
    pub fn ub_ctx_hosts(ctx: *mut ub_ctx, fname: *const c_char) -> c_int;
    pub fn ub_ctx_add_ta_file(ctx: *mut ub_ctx, fname: *const c_char) -> c_int;
    pub fn ub_resolve(ctx: *mut ub_ctx, name: *const c_char, rrtype: c_int, rrclass: c_int, result: *mut *mut ub_result) -> c_int;
    pub fn ub_strerror(err: c_int) -> *const c_char;
}

unsafe fn get_ub_strerror(err: c_int) -> String {
    CStr::from_ptr(ub_strerror(err)).to_string_lossy().into_owned()
}

pub unsafe fn create_ub_ctx() -> Option<*mut ub_ctx> {
    let mut ctx = ub_ctx_create();
    
    if ctx.is_null() {
        eprintln!("Failed to create context");
        // FIXME: leak of ctx
        return None;
    }

    if ub_ctx_resolvconf(ctx, ptr::null()) != 0 {
        eprintln!("Failed to load resolv.conf");
        // FIXME: leak of ctx
        return None;
    }
    
    let hosts = "/etc/hosts\0";
    let retval = ub_ctx_hosts(ctx, hosts.as_ptr() as *const i8);
    if retval != 0 {
        eprintln!("Failed to load hosts: {}", get_ub_strerror(retval));
        // FIXME: leak of ctx
        return None;
    }
    
    let ta_file = "/etc/trusted-key.key\0";
    let retval = ub_ctx_add_ta_file(ctx, ta_file.as_ptr() as *const i8);
    if retval != 0 {
        eprintln!("Failed to load ta_file: {}", get_ub_strerror(retval));
        // FIXME: leak of ctx
        return None;
    }

    eprintln!("Successfully created unbound context");

    Some(ctx)
}

