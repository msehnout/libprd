#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Return value from the process of key validation
 */
typedef enum {
  VALID = 1,
  REVOKED = 2,
  PROVEN_NONEXISTENCE = 3,
  RESULT_NOT_SECURE = 4,
  BOGUS_RESULT = 5,
  ERROR = 9,
} Validity;

/**
 * The main object responsible for validation. Provided as an opaque struct for the C API.
 */
typedef struct Validator Validator;

/**
 * PGP key parsed into a pair of C strings (email, b64 encoded key)
 */
typedef struct {
  const char *email;
  const char *b64_key;
} KeyInfoC;

/**
 * Create a validator context, returns a pointer to a heap allocated structure
 */
Validator *prd_validator_create(void);

/**
 * Destroy the context
 */
void prd_validator_destroy(Validator *ptr);

/**
 * Validate a GPG key passed to the function as the KeyInfoC structure
 */
Validity prd_validator_validate(Validator *validator, const KeyInfoC *key_info);
