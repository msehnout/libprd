#include <stdio.h>
#include "library.h"

const char* fedora_key = "557d8ff0f0f4c6c9fc7140670cc85400dcee5aeb1ac2412e90f41e45._openpgpkey.fedoraproject.org";

int main() {
    printf("ahoj\n");
    hello();
    fetch_pgp_key(fedora_key);
}
