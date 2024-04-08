#include <iostream>
#include <vector>
extern "C"{                 // we need this otherwise it can't find the functions
#include "crypto_aead.h"
}
#include <api.h>
#include <vector>
#include <array>
#include <cassert>

using ustring = std::basic_string<unsigned char>;

inline const unsigned char* uc_str(const char* s) {
    return reinterpret_cast<const unsigned char*>(s);
}


ustring encrypt(const ustring& input, const ustring& associatedData,
    const std::array<unsigned char, CRYPTO_NPUBBYTES>& nonce,
    const std::array<unsigned char, CRYPTO_KEYBYTES>& key
    ) {

    unsigned long long clen = CRYPTO_ABYTES;

    ustring encrypted;
    encrypted.resize(input.size() * 2);

    crypto_aead_encrypt(encrypted.data(), &clen, input.data(), input.size(),
        associatedData.data(), associatedData.size(), (const unsigned char*)0,
        nonce.data(), key.data());
    

    return encrypted;
}

ustring decrypt(const ustring& encrypted, const ustring& associatedData,
    const std::array<unsigned char, CRYPTO_NPUBBYTES>& nonce,
    const std::array<unsigned char, CRYPTO_KEYBYTES>& key
) {

    ustring decrypted;
    decrypted.resize(encrypted.size());

    auto outsize = decrypted.size();

    crypto_aead_decrypt(decrypted.data(), &outsize, (unsigned char*)0, encrypted.data(), encrypted.size(),
        associatedData.data(), associatedData.size(), nonce.data(), key.data());

    return decrypted;
}

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

    ustring associatedData{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    std::array<unsigned char, CRYPTO_NPUBBYTES> nonce{ 0, 1, 2,  3,  4,  5,  6,  7, 8, 9, 10, 11, 12, 13, 14, 15 };
    std::array<unsigned char, CRYPTO_KEYBYTES> key{ 0, 1, 2,  3,  4,  5,  6,  7, 8, 9, 10, 11, 12, 13, 14, 15 };

    auto encrypted = encrypt(uc_str("hello"), associatedData,nonce,key);
    auto decrypted = decrypt(encrypted, associatedData, nonce, key);

    int x = 0;
}
