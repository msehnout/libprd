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

/* A test case that does nothing and succeeds. */
static void email_to_domain(void **state) {
    char* test = prd_email_to_domain(fedora_email);
    assert_memory_equal(test, fedora_key_domain, strlen(fedora_key_domain));
}
int main(void) {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(email_to_domain),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}