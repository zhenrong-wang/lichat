#pragma once

#include <array>
#include <unordered_map>

namespace lichat {
struct session_pool_stats {
    size_t total    = 0;
    size_t empty    = 0;
    size_t recycled = 0;
    size_t prepared = 0;
    size_t active   = 0;
};

class session_pool {
    std::unordered_map<uint64_t, session_item> sessions;
    session_pool_stats                         stats;

    uint64_t gen_64bit_key()
    {
        std::array<uint8_t, 8> hash_key;
        randombytes_buf(hash_key.data(), hash_key.size());
        uint64_t ret = 0;
        for (uint8_t i = 0; i < 8; ++i) ret |= (static_cast<uint64_t>(hash_key[i]) << (i * 8));
        return ret;
    }

public:
    session_pool() : stats({0, 0, 0, 0, 0}) {};

    int prepare_add_session(std::array<uint8_t, CID_BYTES>&                  recv_client_cid,
                            std::array<uint8_t, crypto_box_PUBLICKEYBYTES>&  recv_client_public_key,
                            std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>& recv_client_sign_key, const key_mgr_25519& key_mgr)
    {
        if (!key_mgr.is_activated())
            return -1;
        uint64_t key = lc_utils::hash_client_info(recv_client_cid, recv_client_public_key);
        if (sessions.find(key) != sessions.end())
            return 1;
        session_item session(key);
        session.prepare(recv_client_cid, recv_client_public_key, recv_client_sign_key, key_mgr, true);
        sessions.insert({key, session});
        ++stats.total;
        ++stats.prepared;
        return 0;
    }

    session_item* get_session(uint64_t key)
    {
        auto it = sessions.find(key);
        if (it != sessions.end())
            return &(*it).second;
        return nullptr;
    }

    const bool is_session_stored(uint64_t key)
    {
        return (get_session(key) != nullptr);
    }

    void update_stats_at_session_delete(int status)
    {
        --stats.total;
        if (status == 0 || status == 1)
            --stats.empty;
        else if (status == 2)
            --stats.prepared;
        else if (status == 3)
            --stats.active;
        else
            --stats.recycled;
    }

    bool delete_session(uint64_t key)
    {
        auto ptr = get_session(key);
        if (ptr == nullptr)
            return false;
        auto status = ptr->get_status();
        sessions.erase(key);
        update_stats_at_session_delete(status);
        return true;
    }

    int activate_session(uint64_t key)
    {
        auto ptr = get_session(key);
        if (ptr == nullptr)
            return -1;
        if (ptr->activate()) {
            ++stats.active;
            --stats.prepared;
            return 0;
        }
        return 1;
    }

    std::unordered_map<uint64_t, session_item>& get_session_map()
    {
        return sessions;
    }

    struct session_pool_stats& get_stats()
    {
        return stats;
    }
};
} // namespace lichat