#include <iostream>
#include <vector>
extern "C"{                 // we need this otherwise it can't find the functions
#include "crypto_aead.h"
}
#include <api.h>

int main() {

    unsigned char n[CRYPTO_NPUBBYTES] = { 0, 1, 2,  3,  4,  5,  6,  7,
                                      8, 9, 10, 11, 12, 13, 14, 15 };
    unsigned char k[CRYPTO_KEYBYTES] = { 0, 1, 2,  3,  4,  5,  6,  7,
                                        8, 9, 10, 11, 12, 13, 14, 15 };
    unsigned char a[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    unsigned char m[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    unsigned char c[32], h[32], t[32];
    unsigned long long alen = 16;
    unsigned long long mlen = 16;
    unsigned long long clen = CRYPTO_ABYTES;
    int result = 0;

    result |= crypto_aead_encrypt(c, &clen, m, mlen, a, alen, (const unsigned char*)0, n, k);
    result |= crypto_aead_decrypt(m, &mlen, (unsigned char*)0, c, clen, a, alen, n, k);
}
