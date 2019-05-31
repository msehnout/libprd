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

    if(ub_ctx_resolvconf(ctx, NULL))
        printf("Failed to load resolv.conf");

    /* query for webserver */
    retval = ub_resolve(ctx, domain,
                        61 /* TYPE OPENPGPKEY */,
                        1 /* CLASS IN (internet) */, &result);
    if(retval != 0) {
        printf("resolve error: %s\n", ub_strerror(retval));
        return;
    }

    printf("qname: %s, qtype: %d, qclass: %d, rcode: %d\n", result->qname, result->qtype, result->qclass, result->rcode);

    /* show first result */
    if(result->havedata)
        printf("The key is %s\n", result->data[0]);
    else
        printf("There is no data in the result.");

    if(result->nxdomain)
        printf("NXDOMAIN");

    printf("end");

    ub_resolve_free(result);
    ub_ctx_delete(ctx);
}