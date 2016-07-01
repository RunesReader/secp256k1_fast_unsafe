// Copyright (c) 2016 Llamasoft

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "timer.h"

// This is a bit unconventional... but hey, this is a benchmark harness, not production code
#include "libsecp256k1-config.h"
#include "secp256k1.c"


// Takes a 32 byte private key and returns a 65 or 33 byte uncompressed public key
void secp256k1_privkey_to_pubkey(secp256k1_context *ctx, unsigned char *privkey, unsigned char *pubkey, unsigned int compressed) {
    secp256k1_pubkey tmp;
    size_t pubkey_len = 65;
    unsigned int pubkey_type = ( compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED );

    // Convert the private key to an internal public key representation
    if ( !secp256k1_ec_pubkey_create(ctx, &tmp, privkey) ) { return; }

    // Convert the internal public key representation to a serialized byte format
    secp256k1_ec_pubkey_serialize(ctx, pubkey, &pubkey_len, &tmp, pubkey_type);
}


// Hackishly converts an uncompressed public key to a compressed public key
// The input is considered 65 bytes, the output should be considered 33 bytes
void secp256k1_pubkey_uncomp_to_comp(unsigned char *pubkey) {
    pubkey[0] = 0x02 | (pubkey[64] & 0x01);
}



int main(int argc, char **argv) {
    // Number of iterations as 2^N
    int iter_exponent = ( argc > 1 ? atoi(argv[1]) : 18 );
    int iterations = (1 << iter_exponent);
    struct timespec clock_start;
    double clock_diff;


    // Initializing secp256k1 context
    clock_start = get_clock();
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
    clock_diff = get_clockdiff_s(clock_start);
    printf("context = %12.8f\n", clock_diff);
    printf("\n");


    // Do a quick result verification
    srand(0xDEADBEEF);
    unsigned char privkey[32] = {
        // generated using srand(31415926), first 256 calls of rand() & 0xFF
        0xb9, 0x43, 0x14, 0xa3, 0x7d, 0x33, 0x46, 0x16, 0xd8, 0x0d, 0x62, 0x1b, 0x11, 0xa5, 0x9f, 0xdd,
        0x13, 0x56, 0xf6, 0xec, 0xbb, 0x9e, 0xb1, 0x9e, 0xfd, 0xe6, 0xe0, 0x55, 0x43, 0xb4, 0x1f, 0x30
    };

    unsigned char expected[65] = {
        0x04, 0xfa, 0xf4, 0x5a, 0x13, 0x1f, 0xe3, 0x16, 0xe7, 0x59, 0x78, 0x17, 0xf5, 0x32, 0x14, 0x0d,
        0x75, 0xbb, 0xc2, 0xb7, 0xdc, 0xd6, 0x18, 0x35, 0xea, 0xbc, 0x29, 0xfa, 0x5d, 0x7f, 0x80, 0x25,
        0x51, 0xe5, 0xae, 0x5b, 0x10, 0xcf, 0xc9, 0x97, 0x0c, 0x0d, 0xca, 0xa1, 0xab, 0x7d, 0xc1, 0xb3,
        0x40, 0xbc, 0x5b, 0x3d, 0xf6, 0x87, 0xa5, 0xbc, 0xe7, 0x26, 0x67, 0xfd, 0x6c, 0xe6, 0xc3, 0x66, 0x29
    };

    unsigned char pubkey[65];
    secp256k1_privkey_to_pubkey(ctx, privkey, pubkey, 0);
    if ( memcmp(expected, pubkey, 65) == 0 ) {
        printf("pubkey quick test passed\n");
    } else {
        printf("pubkey quick test failed\n");
        return 1;
    }
    printf("\n");



    // Actual benchmark loop
    printf("iterations = 2^%d (%d)\n", iter_exponent, iterations);
    clock_start = get_clock();
    for (size_t iter = 0; iter < iterations; iter++) {
        // Randomize a byte to ensure differing code paths
        privkey[ iter % 32 ] = rand() & 0xFF;
        secp256k1_privkey_to_pubkey(ctx, privkey, pubkey, 0);
    }
    clock_diff = get_clockdiff_s(clock_start);


    // Benchmark results
    printf("pubkey total = %12.8f\n", clock_diff);
    printf("pubkey avg   = %12.8f\n", clock_diff / iterations);
    printf("pubkey/sec   = %12.2f\n", iterations / clock_diff);
    printf("\n");

    return 0;
}