#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "libprd.h"

const char* fedora_email = "fedora-29@fedoraproject.org";
const char* fedora_key_domain = "557d8ff0f0f4c6c9fc7140670cc85400dcee5aeb1ac2412e90f41e45._openpgpkey.fedoraproject.org";

/*
 * A simple test case to try conversion from an email address to a domain.
 */
static void email_to_domain(void **state) {
    char* test = prd_email_to_domain(fedora_email);
    assert_memory_equal(test, fedora_key_domain, strlen(fedora_key_domain));
}

/*
 * Try to get f29 primary key from DNS a compare it with the expected key. This test requires network connection
 * as it performs DNS query. It should work just fine with any network connection when used with the testing
 * environment because it uses local resolver with forwarding over TLS.
 */
static void fetch_f29_key_from_dns(void **state) {
    struct prd_ctx* c = prd_ctx_create();
    prd_fetch_pgp_key(c, prd_email_to_domain(fedora_email));
    prd_ctx_delete(c);
}

int main(void) {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(email_to_domain),
            cmocka_unit_test(fetch_f29_key_from_dns),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}