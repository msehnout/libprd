#include <stdio.h>
#include <stdlib.h>
#include "libprd.h"

const char* fedora_email = "fedora-29@fedoraproject.org";
const char* fedora_key_domain = "557d8ff0f0f4c6c9fc7140670cc85400dcee5aeb1ac2412e90f41e45._openpgpkey.fedoraproject.org";

int main() {
    printf("ahoj\n");
    hello();
    // struct prd_ctx* ctx = prd_ctx_create();
    // prd_fetch_pgp_key(ctx, fedora_key_domain);
    // prd_ctx_delete(ctx);

    char* test = prd_email_to_domain(fedora_email);
    printf("%s\n", test);
    printf("%s\n", fedora_key_domain);
    free(test);
}
