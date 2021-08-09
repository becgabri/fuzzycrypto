#include <inttypes.h>

typedef struct
{
    uint16_t b1;
    uint8_t b2;
} tiny;

typedef tiny InputB;

int mpc_main(int INPUT_A, InputB INPUT_B) {

    int someB = INPUT_B.b1 + INPUT_B.b2;

    return INPUT_A + someB;
}

