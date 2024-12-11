#ifndef LC_COMMON_H
#define LC_COMMON_H

#include <regex>
#include <array>
#include <vector>
#include <cstring>
#include "sodium.h"
#include "lc_consts.hpp"
#include <iostream>

namespace lc_utils {

    static uint64_t hash_client_info(const std::array<uint8_t, CID_BYTES>& client_cid, const std::array<uint8_t, crypto_box_PUBLICKEYBYTES>& client_public_key) {
        uint8_t hash[CIF_BYTES];
        std::array<uint8_t, CID_BYTES + crypto_box_PUBLICKEYBYTES> client_info;
        std::copy(client_cid.begin(), client_cid.end(), client_info.begin());
        std::copy(client_public_key.begin(), client_public_key.end(), client_info.begin() + CID_BYTES);
        crypto_generichash(hash, CIF_BYTES, client_info.data(), client_info.size(), nullptr, 0);
        uint64_t ret = 0;
        for(uint8_t i = 0; i < CIF_BYTES; ++ i)
            ret |= (static_cast<uint64_t>(hash[i]) << (i << 3));
        return ret;
    }

    static std::vector<std::string> split_buffer_by_null(const uint8_t *data, const size_t data_bytes, const size_t max_items) {
        std::vector<std::string> ret;
        const uint8_t *start = data;
        const uint8_t *end = data + data_bytes;
        const uint8_t *current = start;
        while(current < end && ret.size() <= max_items) {
            auto next_null = static_cast<const uint8_t *>(std::memchr(current, 0x00, (end - current)));
            if(next_null != nullptr) {
                size_t length = next_null - current;
                ret.emplace_back(reinterpret_cast<const char *>(current), length);
                current = next_null + 1;
            }
            else {
                size_t length = end - current;
                if(length > 0) 
                    ret.emplace_back(reinterpret_cast<const char *>(current), length);
                break;
            }
        }
        return ret;
    }

    static std::array<uint8_t, 8> u64_to_bytes(uint64_t num) {
        std::array<uint8_t, 8> ret;
        for(uint8_t i = 0; i < 8; ++ i) 
            ret[i] = static_cast<uint8_t>((num >> (i << 3)) & 0xFF);
        return ret;
    }

    static uint64_t bytes_to_u64(std::array<uint8_t, 8> arr) {
        uint64_t num = 0;
        for(uint8_t i = 0; i < 8; ++ i)
            num |= (static_cast<uint64_t>(arr[i]) << (i << 3));
        return num;
    }

    static void generate_aes_nonce(std::array<uint8_t, crypto_aead_aes256gcm_NPUBBYTES>& aes256gcm_nonce) {
        randombytes_buf(aes256gcm_nonce.data(), aes256gcm_nonce.size());
    }

    // Only Alphabet, numbers, and special chars are allowed.
    // Length: 8-64
    static int pass_fmt_check(const std::string& pass_str) {
        if(pass_str.size() < PASSWORD_MIN_BYTES || pass_str.size() > PASSWORD_MAX_BYTES)
            return -1; // Length error.
        uint8_t contain_num = 0;
        uint8_t contain_lower_char = 0;
        uint8_t contain_special_char = 0;
        uint8_t contain_upper_char = 0;
        for(auto c : pass_str) {
            if(std::isdigit(static_cast<unsigned char>(c))) {
                contain_num = 1;
                continue;
            }
            if(std::islower(static_cast<unsigned char>(c))) {
                contain_lower_char = 1;
                continue;
            }
            if(std::isupper(static_cast<unsigned char>(c))) {
                contain_upper_char = 1;
                continue;
            }
            if(std::find(special_chars.begin(), special_chars.end(), c) != special_chars.end()) {
                contain_special_char = 1;
                continue;
            }
            return 1; // Illegal char found.
        }
        if(contain_num + contain_special_char + contain_lower_char + contain_upper_char < 3)
            return 2; // Not complex enough.
        return 0; // Good to go.
    }

    // Only Alphabet, numbers, and hyphen are allowed.
    // Length: 4-64
    static int user_name_fmt_check(const std::string& uname) {
        if(uname.size() < ULOGIN_MIN_BYTES || uname.size() > UNAME_MAX_BYTES)
            return -1; // Length error.
        for(auto c : uname) {
            if(!std::isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_')
                return 1; // Illegal char found.
        }
        return 0; // Good to go.
    }

    static bool pass_hash(std::string& password, std::array<char, crypto_pwhash_STRBYTES>& hashed_pwd) {
        auto ret = 
        crypto_pwhash_str(
            hashed_pwd.data(), 
            password.c_str(), 
            password.size(), 
            crypto_pwhash_OPSLIMIT_INTERACTIVE, 
            crypto_pwhash_MEMLIMIT_INTERACTIVE
        );
        password.clear(); // For security reasons, we clean the string after hashing.
        if(ret == 0)
            return true;
        return false;
    }

    static int email_fmt_check(const std::string& email) {
        if(email.empty() || email.size() > UEMAIL_MAX_BYTES)
            return -1;
        std::regex email_regex(R"(^[a-zA-Z0-9_.+-]+@(?:[a-z0-9-]+\.)+[a-zA-Z0-9-]{2,}$)");
        if(!std::regex_match(email, email_regex)) 
            return 1;
        return 0;
    }
}

#endif