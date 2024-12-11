#ifndef LC_SESMGR_HPP
#define LC_SESMGR_HPP

#include <array>
#include <iostream>
#include "lc_consts.hpp"
#include "lc_keymgr.hpp"
#include <netdb.h>

// We use AES256-GCM algorithm here
class session_item {
    // Received
    std::array<uint8_t, CID_BYTES> client_cid;
    std::array<uint8_t, crypto_box_PUBLICKEYBYTES> client_public_key;

    // Generated
    uint64_t cinfo_hash; // Will be the unique key for unordered_map.
    std::array<uint8_t, SID_BYTES> server_sid;
    std::array<uint8_t, crypto_aead_aes256gcm_KEYBYTES> aes256gcm_key;

    struct sockaddr_in src_addr;   // the updated source_ddress. 

    //  0 - empty
    //  1 - prepared: cid + public_key + real cinfo_hash + server_sid + AES_key
    //  2 - activated
    int status; 
public:
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

    // Disable the default constructor
    session_item() : status(0) {}

    // Provide a random cinfo_hash but no client info.
    session_item(const uint64_t& precalc_cinfo_hash) : status(0) {
        cinfo_hash = precalc_cinfo_hash;
    }

    const struct sockaddr_in& get_src_addr() const {
        return src_addr;
    }
    void set_src_addr(const sockaddr_in& addr) {
        src_addr = addr;
    }
    const std::array<uint8_t, crypto_aead_aes256gcm_KEYBYTES>& get_aes_gcm_key() const {
        return aes256gcm_key;
    }
    const std::array<uint8_t, CID_BYTES>& get_client_cid() const {
        return client_cid;
    }
    const std::array<uint8_t, SID_BYTES>& get_server_sid() const {
        return server_sid;
    }
    const std::array<uint8_t, crypto_box_PUBLICKEYBYTES>& get_client_public_key() const {
        return client_public_key;
    }
    const int& get_status() const {
        return status;
    }
    int prepare(std::array<uint8_t, CID_BYTES>& recv_client_cid, std::array<uint8_t, crypto_box_PUBLICKEYBYTES>& recv_client_public_key, const curve25519_key_mgr& key_mgr, bool is_precalc_hash) {
        if(!key_mgr.is_activated())
            return -1;
        if(status != 0)
            return 1;
        client_cid = recv_client_cid;
        client_public_key = recv_client_public_key;
        if(!is_precalc_hash) 
            cinfo_hash = hash_client_info(recv_client_cid, recv_client_public_key);
        randombytes_buf(server_sid.data(), server_sid.size());
        if(crypto_box_beforenm(aes256gcm_key.data(), client_public_key.data(), key_mgr.get_secret_key().data()) != 0)
            return 3;
        status = 1;
        return 0;
    }
    bool activate() {
        if(status != 1) 
            return false;
        status = 2;
        return true;
    }
};

#endif