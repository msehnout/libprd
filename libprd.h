#ifndef _LIBPRD_H
#define _LIBPRD_H

#include <unbound.h>

void hello(void);

struct prd_ctx {
    struct ub_ctx* unbound_ctx;
};

struct prd_ctx* prd_ctx_create();
void prd_ctx_delete(struct prd_ctx* ctx);
char* prd_email_to_domain(const char* email);
void prd_fetch_pgp_key(struct prd_ctx* ctx, const char* domain);

#endif //_LIBPRD_H