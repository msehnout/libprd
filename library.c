#include "library.h"

#include <stdio.h>
#include <arpa/inet.h>  /* for inet_ntoa */
#include <unbound.h>

void hello(void) {
    printf("Hello, World!\n");
}

void fetch_pgp_key(const char* domain) {
    struct ub_ctx* ctx;
    struct ub_result* result;
    int retval;

    /* create context */
    ctx = ub_ctx_create();
    if(!ctx) {
        printf("error: could not create unbound context\n");
        return;
    }

    /* query for webserver */
    retval = ub_resolve(ctx, domain,
                        61 /* TYPE OPENPGPKEY */,
                        1 /* CLASS IN (internet) */, &result);
    if(retval != 0) {
        printf("resolve error: %s\n", ub_strerror(retval));
        return;
    }

    /* show first result */
    if(result->havedata)
        printf("The key is %s\n", result->data[0]);

    printf("end");

    ub_resolve_free(result);
    ub_ctx_delete(ctx);
}