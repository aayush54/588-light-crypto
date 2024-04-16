// Filename: decrypt_payload.h

#ifndef DECRYPT_PAYLOAD_H
#define DECRYPT_PAYLOAD_H

#include <string>
#include <vector>
#include <array>

extern "C"{                 // we need this otherwise it can't find the functions
#include "crypto_aead.h"
// #include <openssl/evp.h>
// #include <openssl/aes.h>
// #include <openssl/err.h>
#include <api.h>
}

template <typename Status, typename Command, typename Video>
class Payload {
public:
    Payload(){
        std::vector<std::string> status_topics = {"/pose/heave", "/pose/yaw"};
        std::vector<std::string> command_topics = {"/output_wrench/surge", "/output_wrench/sway", "/output_wrench/heave", "/output_wrench/yaw", "/output_wrench/pitch", "/output_wrench/roll"};
        std::vector<std::string> video_topics = {"/zed2/zed_node/rgb/image_rect_color"};

        for (const std::string &topic : status_topics)
        {
            status_subs.emplace_back(topic);
        }
        for (const std::string &topic : command_topics)
        {
            command_subs.emplace_back(topic);
        }
        for (const std::string &topic : video_topics)
        {
            video_subs.emplace_back(topic);
        }
    }

private:
    std::vector<Status> status_subs;
    std::vector<Command> command_subs;
    std::vector<Video> video_subs;
};


std::string ascon_encrypt(const std::string_view input, const std::string_view associatedData,
    const std::array<unsigned char, CRYPTO_NPUBBYTES>& nonce,
    const std::array<unsigned char, CRYPTO_KEYBYTES>& key);
std::string ascon_decrypt(const std::string_view encrypted, const std::string_view associatedData,
    const std::array<unsigned char, CRYPTO_NPUBBYTES>& nonce,
    const std::array<unsigned char, CRYPTO_KEYBYTES>& key);

void ssl_handleErrors(void);

struct ssl_encrypt_result {
    std::array<unsigned char, 16> tag;
    std::string cipherText;
};

ssl_encrypt_result ssl_encrypt(const std::string_view plaintext, const std::string_view associatedData, 
    const std::array<unsigned char, CRYPTO_KEYBYTES>& key, const std::array<unsigned char, CRYPTO_KEYBYTES>& initializationVector);
std::string ssl_decrypt(ssl_encrypt_result &ssl_encrypted, const std::string_view associatedData, 
    const std::array<unsigned char, CRYPTO_KEYBYTES>& key, const std::array<unsigned char, CRYPTO_KEYBYTES>& initializationVector);

#endif // DECRYPT_PAYLOAD_H