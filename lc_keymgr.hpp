#ifndef LC_KEYMGR_HPP
#define LC_KEYMGR_HPP

#include "lc_consts.hpp"
#include <vector>
#include <sodium.h>     // For libsodium
#include <fstream>
#include <array>
#include <string>
#include <cstring>

class key_mgr_25519 {
    std::array<uint8_t, crypto_box_PUBLICKEYBYTES> crypto_pk;
    std::array<uint8_t, crypto_box_SECRETKEYBYTES> crypto_sk;
    std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> sign_pk;
    std::array<uint8_t, crypto_sign_SECRETKEYBYTES> sign_sk;
    std::string key_dir;
    std::string prefix;
    bool is_empty;
public:
    key_mgr_25519() : is_empty(true), key_dir(default_key_dir) {}

    key_mgr_25519(const std::string& dir, const std::string& pref) : is_empty(true), key_dir(dir), prefix(pref){}

    void set_key_dir(const std::string& dir) {
        key_dir = dir;
    }

    void set_key_dir(const std::string& dir, const std::string& pref) {
        prefix = pref;
    }

    static int read_key_file(const std::string& file_path, std::vector<uint8_t>& content, const std::streamsize& size) {
        std::ifstream file(file_path, std::ios::in | std::ios::binary | std::ios::ate);
        if(!file.is_open())
            return 1; // file open error
        std::streamsize file_size = file.tellg();
        if(file_size != size) {
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
    // In key dir, there would be 4 managed keys:
    // curve25519 pk, curve_25519_sk, ed25519_pk, ed25519_sk.
    int load_local_key_files() {
        std::vector<uint8_t> cpk(crypto_box_PUBLICKEYBYTES), csk(crypto_box_SECRETKEYBYTES);
        std::vector<uint8_t> spk(crypto_sign_PUBLICKEYBYTES), ssk(crypto_sign_SECRETKEYBYTES);
        
        std::string cpk_file = key_dir + "/" + prefix + "crypto_25519.pub";
        std::string csk_file = key_dir + "/" + prefix + "crypto_25519.sec";
        std::string spk_file = key_dir + "/" + prefix + "sign_25519.pub";
        std::string ssk_file = key_dir + "/" + prefix + "sign_25519.sec";

        auto res1 = read_key_file(cpk_file, cpk, cpk.size());
        auto res2 = read_key_file(csk_file, csk, csk.size());
        auto res3 = read_key_file(spk_file, spk, spk.size());
        auto res4 = read_key_file(ssk_file, ssk, ssk.size());

        if(res1 == 0 && res2 == 0 && res3 == 0 && res4 == 0) {
            uint8_t random_msg[32];
            uint8_t enc_msg[crypto_box_SEALBYTES + sizeof(random_msg)];
            uint8_t dec_msg[sizeof(random_msg)];
            uint8_t sign_msg[crypto_sign_BYTES + sizeof(random_msg)];
            unsigned long long signed_len = 0, sign_open_len = 0;
            randombytes_buf(random_msg, sizeof(random_msg));

            crypto_box_seal(enc_msg, random_msg, sizeof(random_msg), cpk.data());
            if(crypto_box_seal_open(dec_msg, enc_msg, sizeof(enc_msg), cpk.data(), csk.data()) != 0)
                return 1;
            if(std::memcmp(random_msg, dec_msg, sizeof(random_msg)) != 0)
                return 3;

            crypto_sign(sign_msg, &signed_len, random_msg, sizeof(random_msg), ssk.data());
            if(crypto_sign_open(nullptr, &sign_open_len, sign_msg, sizeof(sign_msg), spk.data()) != 0)
                return 5;
            std::copy(cpk.begin(), cpk.end(), crypto_pk.begin());
            std::copy(csk.begin(), csk.end(), crypto_sk.begin());
            std::copy(spk.begin(), spk.end(), sign_pk.begin());
            std::copy(ssk.begin(), ssk.end(), sign_sk.begin());
            is_empty = false;
            return 0;
        }
        return -1; // File read error.
    }

    // This is a force operation, no status check.
    int gen_key_save_to_local() {
        std::string cpk_file = key_dir + "/" + prefix + "crypto_25519.pub";
        std::string csk_file = key_dir + "/" + prefix + "crypto_25519.sec";
        std::string spk_file = key_dir + "/" + prefix + "sign_25519.pub";
        std::string ssk_file = key_dir + "/" + prefix + "sign_25519.sec";

        std::ofstream out_cpk(cpk_file, std::ios::binary);
        std::ofstream out_csk(csk_file, std::ios::binary);
        std::ofstream out_spk(spk_file, std::ios::binary);
        std::ofstream out_ssk(ssk_file, std::ios::binary);

        if(!out_cpk.is_open() || !out_csk.is_open() || !out_spk.is_open() || !out_ssk.is_open()) {
            if(out_cpk.is_open()) out_cpk.close();
            if(out_csk.is_open()) out_csk.close();
            if(out_spk.is_open()) out_spk.close();
            if(out_ssk.is_open()) out_ssk.close();
            return -1; // File I/O error.
        }

        std::array<uint8_t, crypto_box_PUBLICKEYBYTES> gen_box_pk;
        std::array<uint8_t, crypto_box_SECRETKEYBYTES> gen_box_sk;
        std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> gen_sign_pk;
        std::array<uint8_t, crypto_sign_SECRETKEYBYTES> gen_sign_sk;

        crypto_box_keypair(gen_box_pk.data(), gen_box_sk.data());
        crypto_sign_keypair(gen_sign_pk.data(), gen_sign_sk.data());

        crypto_pk = gen_box_pk;
        crypto_sk = gen_box_sk;
        sign_pk = gen_sign_pk;
        sign_sk = gen_sign_sk;

        out_cpk.write(reinterpret_cast<const char *>(gen_box_pk.data()), gen_box_pk.size());
        out_csk.write(reinterpret_cast<const char *>(gen_box_sk.data()), gen_box_sk.size());
        out_spk.write(reinterpret_cast<const char *>(gen_sign_pk.data()), gen_sign_pk.size());
        out_ssk.write(reinterpret_cast<const char *>(gen_sign_sk.data()), gen_sign_sk.size());
        
        out_cpk.close();
        out_csk.close();
        out_spk.close();
        out_ssk.close();
        return 0;
    }

    int key_mgr_init() {
        if(!is_empty) 
            return 0; // If already init.
        auto ret = load_local_key_files();
        if(ret != 0) {
            if(gen_key_save_to_local() != 0)
                return 1;
        }
        is_empty = false;
        return 0;
    }

    const std::array<uint8_t, crypto_box_PUBLICKEYBYTES>& get_crypto_pk() const {
        return crypto_pk;
    }

    const std::array<uint8_t, crypto_box_SECRETKEYBYTES>& get_crypto_sk() const {
        return crypto_sk;
    }

    const std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>& get_sign_pk() const {
        return sign_pk;
    }

    const std::array<uint8_t, crypto_sign_SECRETKEYBYTES>& get_sign_sk() const {
        return sign_sk;
    }

    bool is_activated() const {
        return !is_empty;
    }
};

#endif