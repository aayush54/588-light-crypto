#include <iostream>
#include <vector>
#include <vector>
#include <array>
#include <cassert>

extern "C"{                 // we need this otherwise it can't find the functions
#include "crypto_aead.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <api.h>
}


inline const unsigned char* cuc_str(const char* s) {
    return reinterpret_cast<const unsigned char*>(s);
}

inline unsigned char* uc_str(char* s) {
    return reinterpret_cast<unsigned char*>(s);
}


std::string ascon_encrypt(const std::string_view input, const std::string_view associatedData,
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

std::string ascon_decrypt(const std::string_view encrypted, const std::string_view associatedData,
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

// OpenSSL code adapted from: https://stackoverflow.com/questions/9889492/how-to-do-encryption-using-aes-in-openssl
void ssl_handleErrors(void)
{
    unsigned long errCode;

    printf("An error occurred\n");
    while (errCode = ERR_get_error())
    {
        char* err = ERR_error_string(errCode, NULL);
        printf("%s\n", err);
    }
    abort();
}

std::string ssl_encrypt(const std::string_view plaintext, const std::string_view associatedData, const std::array<unsigned char, CRYPTO_KEYBYTES>& key, const std::array<unsigned char, CRYPTO_KEYBYTES>& initializationVector) {

    constexpr auto ssl_encrypt_impl = [](const unsigned char* plaintext, size_t plaintext_len, const unsigned char* aad,
        size_t aad_len, const unsigned char* key, const unsigned char* iv,
        unsigned char* ciphertext, unsigned char* tag) -> int
        {
            EVP_CIPHER_CTX* ctx = NULL;
            int len = 0, ciphertext_len = 0;

            /* Create and initialise the context */
            if (!(ctx = EVP_CIPHER_CTX_new())) ssl_handleErrors();

            /* Initialise the encryption operation. */
            if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
                ssl_handleErrors();

            /* Set IV length if default 12 bytes (96 bits) is not appropriate */
            if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
                ssl_handleErrors();

            /* Initialise key and IV */
            if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) ssl_handleErrors();

            /* Provide any AAD data. This can be called zero or more times as
             * required
             */
            if (aad && aad_len > 0)
            {
                if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
                    ssl_handleErrors();
            }

            /* Provide the message to be encrypted, and obtain the encrypted output.
             * EVP_EncryptUpdate can be called multiple times if necessary
             */
            if (plaintext)
            {
                if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
                    ssl_handleErrors();

                ciphertext_len = len;
            }

            /* Finalise the encryption. Normally ciphertext bytes may be written at
             * this stage, but this does not occur in GCM mode
             */
            if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) ssl_handleErrors();
            ciphertext_len += len;

            /* Get the tag */
            if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
                ssl_handleErrors();

            /* Clean up */
            EVP_CIPHER_CTX_free(ctx);

            return ciphertext_len;
        };

    std::array<unsigned char, 16> tag; // memory for the tag
    std::string encrypted;
    encrypted.resize(plaintext.size() * 2);

    auto length = ssl_encrypt_impl(cuc_str(plaintext.data()), plaintext.size(), cuc_str(associatedData.data()), associatedData.size(), key.data(), initializationVector.data(), uc_str(encrypted.data()), tag.data());

    encrypted.resize(length);

    return encrypted;
}

int ssl_decrypt(unsigned char* ciphertext, int ciphertext_len, const unsigned char* aad,
    int aad_len, unsigned char* tag, unsigned char* key, unsigned char* iv,
    unsigned char* plaintext)
{
    EVP_CIPHER_CTX* ctx = NULL;
    int len = 0, plaintext_len = 0, ret;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) ssl_handleErrors();

    /* Initialise the decryption operation. */
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        ssl_handleErrors();

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
        ssl_handleErrors();

    /* Initialise key and IV */
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) ssl_handleErrors();

    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    if (aad && aad_len > 0)
    {
        if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
            ssl_handleErrors();
    }

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if (ciphertext)
    {
        if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
            ssl_handleErrors();

        plaintext_len = len;
    }

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        ssl_handleErrors();

    /* Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0)
    {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    }
    else
    {
        /* Verify failed */
        return -1;
    }
}

int main() {

    // openssl stuff that needs to happen before you do anything
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    std::string associatedData{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    std::array<unsigned char, CRYPTO_NPUBBYTES> nonce{ 0, 1, 2,  3,  4,  5,  6,  7, 8, 9, 10, 11, 12, 13, 14, 15 };
    std::array<unsigned char, CRYPTO_KEYBYTES> key{ 0, 1, 2,  3,  4,  5,  6,  7, 8, 9, 10, 11, 12, 13, 14, 15 };

    std::string_view input = "this is a string that is longer than 16 bytes and should still make it through unscathed";

    auto encrypted = ascon_encrypt(input, associatedData,nonce,key);
    auto decrypted = ascon_decrypt(encrypted, associatedData, nonce, key);

    std::cout << "encrypted size: " << encrypted.size() << std::endl;
    std::cout << decrypted << std::endl;


    encrypted = ssl_encrypt(input, associatedData, key, nonce);
    std::cout << "opessl encrypted size" << encrypted.size() << std::endl;
}
