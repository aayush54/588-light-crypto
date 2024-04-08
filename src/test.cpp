#include <iostream>
#include <vector>
extern "C"{                 // we need this otherwise it can't find the functions
#include "crypto_aead.h"
}
#include <api.h>
#include <vector>
#include <array>
#include <cassert>


inline const unsigned char* cuc_str(const char* s) {
    return reinterpret_cast<const unsigned char*>(s);
}

inline unsigned char* uc_str(char* s) {
    return reinterpret_cast<unsigned char*>(s);
}


std::string ascon_encrypt(const std::string& input, const std::string& associatedData,
    const std::array<unsigned char, CRYPTO_NPUBBYTES>& nonce,
    const std::array<unsigned char, CRYPTO_KEYBYTES>& key
    ) {

    unsigned long long clen = input.size() + CRYPTO_ABYTES;

    std::string encrypted;
    encrypted.resize(clen);

    crypto_aead_encrypt(uc_str(encrypted.data()), &clen, cuc_str(input.data()), input.size(),
        cuc_str(associatedData.data()), associatedData.size(), (const unsigned char*)0,
        nonce.data(), key.data());
    
    encrypted.resize(clen);

    return encrypted;
}

std::string ascon_decrypt(const std::string& encrypted, const std::string& associatedData,
    const std::array<unsigned char, CRYPTO_NPUBBYTES>& nonce,
    const std::array<unsigned char, CRYPTO_KEYBYTES>& key
) {

    std::string decrypted;
    decrypted.resize(encrypted.size());

    auto outsize = decrypted.size();

    crypto_aead_decrypt(uc_str(decrypted.data()), &outsize, (unsigned char*)0, cuc_str(encrypted.data()), encrypted.size(),
        cuc_str(associatedData.data()), associatedData.size(), nonce.data(), key.data());

    return decrypted;
}

int main() {

    std::string associatedData{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    std::array<unsigned char, CRYPTO_NPUBBYTES> nonce{ 0, 1, 2,  3,  4,  5,  6,  7, 8, 9, 10, 11, 12, 13, 14, 15 };
    std::array<unsigned char, CRYPTO_KEYBYTES> key{ 0, 1, 2,  3,  4,  5,  6,  7, 8, 9, 10, 11, 12, 13, 14, 15 };

    auto encrypted = ascon_encrypt("hello", associatedData,nonce,key);
    auto decrypted = ascon_decrypt(encrypted, associatedData, nonce, key);

    std::cout << "encrypted size: " << encrypted.size() << std::endl;
    std::cout << decrypted << std::endl;

}
