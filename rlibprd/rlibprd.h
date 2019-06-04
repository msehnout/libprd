#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef enum {
  VALID = 1,
  REVOKED = 2,
  PROVEN_NONEXISTENCE = 3,
  RESULT_NOT_SECURE = 4,
  BOGUS_RESULT = 5,
  ERROR = 9,
} Validity;

typedef struct Validator Validator;

typedef struct {
  const char *email;
  const char *b64_key;
} KeyInfoC;

Validator *prd_validator_create(void);

void prd_validator_destroy(Validator *ptr);

Validity prd_validator_validate(Validator *validator, const KeyInfoC *key_info);