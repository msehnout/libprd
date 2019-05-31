#include "libprd.h"

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>  /* for inet_ntoa */
#include <errno.h>
#include <string.h>
#include <unbound.h>
#include <openssl/sha.h>

void hello(void) {
    printf("Hello, World!\n");
}

struct prd_ctx* prd_ctx_create() {
    struct prd_ctx* return_context = (struct prd_ctx *)malloc(sizeof(struct prd_ctx));
    struct ub_ctx* ctx;
    int retval;

    /* create unbound context */
    ctx = ub_ctx_create();
    if(!ctx) {
        printf("error: could not create unbound context\n");
        goto fail;
    }

    /* load configuration from /etc/resolv.conf */
    if(ub_ctx_resolvconf(ctx, NULL))
        printf("Failed to load resolv.conf\n");

    /* read /etc/hosts for locally supplied host addresses */
    if( (retval=ub_ctx_hosts(ctx, "/etc/hosts")) != 0) {
        printf("error reading hosts: %s. errno says: %s\n",
               ub_strerror(retval), strerror(errno));
        goto fail;
    }

    /* read public keys for DNSSEC verification */
    if( (retval=ub_ctx_add_ta_file(ctx, "/etc/trusted-key.key")) != 0) {
        printf("error adding keys: %s\n", ub_strerror(retval));
        goto fail;
    }

    return_context->unbound_ctx = ctx;
    return return_context;

fail:
    free(return_context);
    return NULL;
}

void prd_ctx_delete(struct prd_ctx* ctx) {
    ub_ctx_delete(ctx->unbound_ctx);
    free(ctx);
}

char* prd_email_to_domain(const char* email) {
    char* ret = (char *)calloc('\0', 1000);
    const char* at_sign = NULL;

    at_sign = email;
    while (*at_sign != '@') {
        /* The @ sign does not exist in the given string. */
        if (*at_sign == '\0')
            return NULL;

        at_sign++;
    }

    unsigned char md[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)email, at_sign-email, md);
    printf("HASH:");
    for(size_t i=0; i<SHA256_DIGEST_LENGTH; i++) {
        printf("%x", md[i]);
    }
    printf("\n");

    for(size_t i=0; i<28; i++) {
        sprintf(ret+i, "%02X", md[i]);
    }

    strcpy(ret+28, "._openpgpkey.");
    strcpy(ret+41, at_sign+1);

    return ret;
}

void prd_fetch_pgp_key(struct prd_ctx *ctx, const char *domain) {
    struct ub_result* result;
    int retval;

    /* query for the key */
    retval = ub_resolve(ctx->unbound_ctx, domain,
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
        printf("There is no data in the result.\n");

    if(result->nxdomain)
        printf("NXDOMAIN\n");

    if(result->secure)
        printf("SECURE\n");
    else
        printf("NOT SECURE\n");

    printf("end\n");

    ub_resolve_free(result);
}