#ifndef LC_KEYMGR_HPP
#define LC_KEYMGR_HPP

#include <vector>
#include <sodium.h>     // For libsodium
#include <fstream>
#include <array>
#include <cstring>

class curve25519_key_mgr {
    std::array<uint8_t, crypto_box_PUBLICKEYBYTES> public_key;
    std::array<uint8_t, crypto_box_SECRETKEYBYTES> secret_key;
    bool is_empty;
public:
    curve25519_key_mgr() : is_empty(true) {}
    
    static int read_curve25519_key_file(const std::string& file_path, std::vector<uint8_t>& content, const std::streamsize& expected_size) {
        if(expected_size != crypto_box_PUBLICKEYBYTES && expected_size != crypto_box_SECRETKEYBYTES)
            return -1; // function call error
        std::ifstream file(file_path, std::ios::in | std::ios::binary | std::ios::ate);
        if(!file.is_open())
            return 1; // file open error
        std::streamsize size = file.tellg();
        if(size != expected_size) {
            file.close();
            return 3; // file size error
        }
        file.seekg(0, std::ios::beg);
        content.resize(size);
        if(!file.read(reinterpret_cast<char *>(content.data()), size)) {
            file.close();
            return 5; // file read error
        }
        file.close();
        return 0; // This doesn't mean the keys are valid, only format is correct.
    }

    // This is a force operation, no status check
    int load_local_key_files(std::string& pub_key_file, std::string& priv_key_file) {
        std::vector<uint8_t> public_key_vec, secret_key_vec;
        auto ret = read_curve25519_key_file(pub_key_file, public_key_vec, crypto_box_PUBLICKEYBYTES);
        if(ret != 0)
            return ret; // 1, 3, 5
        ret = read_curve25519_key_file(priv_key_file, secret_key_vec, crypto_box_SECRETKEYBYTES);
        if(ret != 0)
            return -ret; // -1, -3, -5
        uint8_t random_msg[32];
        uint8_t enc_msg[crypto_box_SEALBYTES + sizeof(random_msg)];
        uint8_t dec_msg[sizeof(random_msg)];
        randombytes_buf(random_msg, sizeof(random_msg));
        crypto_box_seal(enc_msg, random_msg, sizeof(random_msg), public_key_vec.data());
        if(crypto_box_seal_open(dec_msg, enc_msg, sizeof(enc_msg), public_key_vec.data(), secret_key_vec.data()) != 0)
            return 7;
        if(std::memcmp(random_msg, dec_msg, sizeof(random_msg)) == 0) {
            std::copy(public_key_vec.begin(), public_key_vec.end(), public_key.begin());
            std::copy(secret_key_vec.begin(), secret_key_vec.end(), secret_key.begin());
            is_empty = false;
            return 0;
        }
        return 7; // key doesn't match
    }

    // This is a force operation, no status check.
    int gen_key_save_to_local(std::string& pub_key_file_path, std::string& sec_key_file_path) {
        std::ofstream out_pub_key(pub_key_file_path, std::ios::binary);
        if(!out_pub_key.is_open())
            return 1;
        std::ofstream out_sec_key(sec_key_file_path, std::ios::binary);
        if(!out_sec_key.is_open()) {
            out_pub_key.close();
            return -1;
        }
        uint8_t gen_public_key[crypto_box_PUBLICKEYBYTES];
        uint8_t gen_secret_key[crypto_box_SECRETKEYBYTES];
        crypto_box_keypair(gen_public_key, gen_secret_key);
        std::copy(std::begin(gen_public_key), std::end(gen_public_key), public_key.begin());
        std::copy(std::begin(gen_secret_key), std::end(gen_secret_key), secret_key.begin());
        is_empty = false;
        out_pub_key.write(reinterpret_cast<const char *>(public_key.data()), public_key.size());
        out_sec_key.write(reinterpret_cast<const char *>(secret_key.data()), secret_key.size());
        out_pub_key.close();
        out_sec_key.close();
        return 0;
    }

    int key_mgr_init(std::string& pub_key_file_path, std::string& sec_key_file_path) {
        if(!is_empty) 
            return 0; // If already init.
        auto ret = load_local_key_files(pub_key_file_path, sec_key_file_path);
        if(ret != 0) {
            if(gen_key_save_to_local(pub_key_file_path, sec_key_file_path) != 0)
                return 1;
        }
        return 0;
    }
    const std::array<uint8_t, crypto_box_SECRETKEYBYTES>& get_secret_key() const {
        return secret_key;
    }
    const std::array<uint8_t, crypto_box_SECRETKEYBYTES>& get_public_key() const {
        return public_key;
    }
    bool is_activated() const {
        return !is_empty;
    }
};

#endif