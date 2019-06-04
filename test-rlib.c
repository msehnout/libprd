#include <stdio.h>
#include "rlibprd/rlibprd.h"

int main() {
	printf("Starting\n");
	Validator* v = prd_validator_create();
	prd_validator_destroy(v);
	printf("Finished\n");
}
