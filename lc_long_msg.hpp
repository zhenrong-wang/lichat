/*
 * Copyright (C) 2022-present Zhenrong WANG
 * This code is distributed under the license: MIT License
 * mailto: zhenrongwang@live.com | X/Twitter: wangzhr4
 */

#include "lc_common.hpp"
#include <stddef.h>
#include <random>
#include <atomic>
#include <unordered_map>

constexpr size_t CHUNK_SIZE_MIN = 64;
constexpr size_t MSG_ID_BYTES = 8;

constexpr size_t SN_WIDTH_BOUNDARY = 256;
constexpr size_t N_CHUNKS_MAX = 65536;
constexpr size_t N_CHUNKS_MID = 256;
constexpr uint8_t DEFAULT_CHUNK_SIZE_MASK = 0x05; // 2048 byte
constexpr uint8_t CHUNK_SIZE_MASK_MAX = 0x09; // 0 ~ 9, 64byte - 32KB
constexpr int RECV_TIMEOUT_RETURN = -6;

constexpr size_t LMSG_BYTES_MIN = 1 + crypto_sign_BYTES + CIF_BYTES + MSG_ID_BYTES;

// Currently, this protocal is for messaging, not for large file 
// transfer, so we set the time window to a short period.
// In the future, if we plan to support large file transfer,
// We would adjust this time window.
// Because the send/recv of long message is blocking, if this window
// is too big, performance would be severly affected.
// Maybe we need to consider threading for large file transfer. But that 
// would need efforts at both server side and client side.
// To make it simple for now, we set the time window to 10.
constexpr size_t LMSG_ALIVE_SECS = 60;

/**
 * MASK_TO_SIZE:
 * 0 - 64
 * 1 - 128
 * 2 - 256
 * 3 - 512
 * 4 - 1024
 * 5 - 2048
 * 6 - 4096
 * 7 - 8192
 * 8 - 16,384
 * 9 - 32,768   // Currently the LiChat only support to this level, 2 GB MAX
 * 10 - 65,536
 * 11 - 131,072
 * 12 - 262,144
 * 13 - 524,288
 * 14 - 1,048,576
 * 15 - 2,097,152
 * 16 - 4,194,304
 * 17 - 8,388,608
 * ...
 * 
 */

class lmsg_receiver {
    uint64_t msg_id;
    std::array<uint8_t, 8> msg_id_bytes;
    bool recv_sn_dwidth;
    int status;     // 0 - receiving, 1 - last_chunk received, 2 - all received, 3 - timeout.
    uint8_t recv_header;
    size_t recv_chunk_size;
    size_t recv_total_chunks;
    std::vector<uint8_t> recv_bitmap;
    std::vector<uint16_t> missing_chunks;
    time_t recv_start_time;
    std::unordered_map<uint16_t, std::vector<uint8_t>> recv_chunks;
    std::vector<std::vector<uint8_t>> recv_chunks_ordered;

public:
    lmsg_receiver () {
        msg_id = 0;
        recv_sn_dwidth = false;
        status = 0;
        recv_header = 0x00;
        recv_chunk_size = 0;
        recv_total_chunks = 0;
        recv_start_time = 0;
    }

    bool is_chunk_received (uint16_t chunk_sn) {
        uint16_t byte = chunk_sn / 8;
        uint8_t bit = chunk_sn % 8;
        return ((recv_bitmap[byte] & (0x80 >> bit)) != 0);
    }

    void record_chunk (uint16_t chunk_sn) {
        uint16_t byte = chunk_sn / 8;
        uint8_t bit = chunk_sn % 8;
        recv_bitmap[byte] |= (0x80 >> bit);
    }

    const std::unordered_map<uint16_t, std::vector<uint8_t>>& 
        get_recv_chunks () const {
        return recv_chunks;
    }

    const std::vector<std::vector<u_int8_t>>& get_recv_chunks_ordered () const {
        return recv_chunks_ordered;
    }

    const std::array<uint8_t, 8>& get_recv_msgid_bytes () const {
        return msg_id_bytes;
    }

    const std::vector<uint16_t>& get_recv_missing_chunks () const {
        return missing_chunks;
    }

    std::vector<uint8_t> missing_chunks_to_bytes () {
        auto bytes = msg_id_bytes.size() + 2 * missing_chunks.size();
        std::vector<uint8_t> ret(bytes);
        std::copy(msg_id_bytes.begin(), msg_id_bytes.end(),
                  ret.begin());
        auto missed = lc_utils::u16vec_to_u8(missing_chunks);
        std::copy(missed.begin(), missed.end(), 
                  ret.begin() + msg_id_bytes.size());
        return ret;
    }

    int check_clear_timeout (time_t now) {
        if (now - recv_start_time > LMSG_ALIVE_SECS) {
            // If the alive seconds passed, clear all contents.
            recv_bitmap.clear();
            missing_chunks.clear();
            recv_chunks.clear();
            recv_chunks_ordered.clear();
            if (status == 0) {
                status = 3;
                return -1;  // Cleared incomplete receiving
            }
            else {
                status = 3;
                return 1;   // Cleared complete receiving
            }
        }
        return 0;   // Nothing cleared, not timeout
    }

    bool is_receiving () {
        return (status == 0 || status == 1);
    }

    bool last_chunk_received () {
        return status == 1;
    }

    bool recv_done () {
        return status == 2;
    }

    bool recv_timeout () {
        return status == 3;
    }

    static uint64_t get_chunk_msg_id (const std::vector<uint8_t>& chunk) {
        if (chunk.size() < sizeof(uint64_t) + 2)
            return false;
        std::array<uint8_t, MSG_ID_BYTES> id_bytes;
        std::copy(chunk.begin(), chunk.begin() + MSG_ID_BYTES, id_bytes.begin());
        return lc_utils::bytes_to_u64(id_bytes);
    }

    // Return:
    // -1 : size error
    // new receive: 
    int receive_chunk (const std::vector<uint8_t>& raw_chunk) {
        if (raw_chunk.size() < sizeof(uint64_t) + 2) 
            return -1;
        std::array<uint8_t, 8> raw_msg_id_bytes;
        uint64_t raw_msg_id;
        auto raw_beg = raw_chunk.begin();
        size_t offset = 0;
        std::copy(raw_beg, raw_beg + 8, raw_msg_id_bytes.begin());
        raw_msg_id = lc_utils::bytes_to_u64(raw_msg_id_bytes);
        offset += 8;
        auto raw_header = raw_chunk[offset];
        
        if (recv_chunks.empty()) {
            (recv_bitmap).clear();     // Prepare the bitmap.
            msg_id = raw_msg_id;       // Record the message id.
            msg_id_bytes = lc_utils::u64_to_bytes(raw_msg_id);
            recv_start_time = lc_utils::now_time();
            recv_total_chunks = 0;
            uint8_t raw_mask = raw_header >> 1;
            if (raw_mask > CHUNK_SIZE_MASK_MAX)
                return -3;   // Invalid mask.
            auto raw_chunk_size = CHUNK_SIZE_MIN << raw_mask;
            bool raw_sn_dwidth = (raw_header & static_cast<uint8_t>(0x01));
            if (raw_sn_dwidth && (offset + 2 > raw_chunk.size()))
                return -5;   // Invalid length.
            if (raw_sn_dwidth)
                recv_bitmap.resize(N_CHUNKS_MAX);
            else 
                recv_bitmap.resize(N_CHUNKS_MID);
            // Record the header.
            recv_header = raw_header;
            recv_sn_dwidth = raw_sn_dwidth;
            recv_chunk_size = raw_chunk_size;
        }
        else {
            if (raw_msg_id != msg_id)    // Compare the message id.
                return -2;
            if (raw_header != recv_header)
                return -4;
            if (check_clear_timeout(lc_utils::now_time()) != 0) 
                return RECV_TIMEOUT_RETURN;
        }
        ++ offset;
        uint16_t raw_chunk_sn;
        if (recv_sn_dwidth) {
            std::array<uint8_t, 2> chunk_sn_bytes;
            std::copy(raw_beg + offset, raw_beg + offset + 2, 
                      chunk_sn_bytes.begin());
            raw_chunk_sn = lc_utils::bytes_to_u16(chunk_sn_bytes);
            offset += 2;
        }
        else {
            raw_chunk_sn = static_cast<uint16_t>(raw_beg[offset]);
            ++ offset;
        }
        if (is_chunk_received(raw_chunk_sn))
            return 2; 
        // Now copy the message body.
        std::vector<uint8_t> chunk_msg(raw_chunk.size() - offset);
        std::copy(raw_beg + offset, raw_chunk.end(), chunk_msg.begin());
        recv_chunks.emplace(raw_chunk_sn, chunk_msg);
        record_chunk(raw_chunk_sn);
        size_t raw_chunk_msg_size = raw_chunk.size() - offset;
        if (raw_chunk_msg_size != recv_chunk_size) {
            // recv_total_chunks = 0 ~ 65536
            recv_total_chunks = static_cast<size_t>(raw_chunk_sn) + 1;
            status = 1;
            return 1;
        }
        return 0;       // Received a normal chunk
    }

    bool check_missing_chunks () {
        if (!last_chunk_received())
            return false;   // If last chunk not received, don't check.
        missing_chunks.clear();
        auto max_byte = recv_total_chunks / 8;
        auto last_bit = recv_total_chunks % 8;
        for (size_t i = 0; i < max_byte; ++ i) {
            if (recv_bitmap[i] == 0xFF)
                continue;
            auto byte = recv_bitmap[i];
            for (size_t j = 0; j < 8; ++ j) {
                if ((byte & (static_cast<uint8_t>(0x80) >> j)) == 0)
                    missing_chunks.push_back(static_cast<uint16_t>(i * 8 + j));
            }
        }
        auto last_byte = recv_bitmap[max_byte];
        for (size_t j = 0; j < last_bit; ++ j) {
            if ((last_byte & (static_cast<uint8_t>(0x80) >> j)) == 0)
                missing_chunks.push_back(static_cast<uint16_t>(max_byte * 8 + j));
        }
        if (missing_chunks.empty())
            status = 2; // All chunks received.
        return true;
    }

    bool order_recv_chunks () {
        if (!recv_done())
            return false;   // Still has missing chunks.
        recv_chunks_ordered.clear();
        recv_chunks_ordered.resize(recv_chunks.size());
        for (const auto it : recv_chunks)
            recv_chunks_ordered[it.first] = it.second;
        return true;
    }
};

class lmsg_recv_pool {
    std::unordered_map<uint64_t, lmsg_receiver> receivers;
    std::vector<uint64_t> trash;

public:
    lmsg_recv_pool () {}

    // -1 : size error
    // -3 : discarded
    // -5 : failed to receive a new long message
    // -7 : failed to receive a chunk
    int add_lmsg (const std::vector<uint8_t>& chunk) {
        if (chunk.size() < MSG_ID_BYTES + 2) 
            return -1;
        std::array<uint8_t, MSG_ID_BYTES> msg_id;
        std::copy(chunk.begin(), chunk.begin() + MSG_ID_BYTES, msg_id.begin());
        auto key = lc_utils::bytes_to_u64(msg_id);
        // Check whether it is a discarded one.
        for (auto k : trash) {
            if (key == k) 
                return -3;
        }
        int recv_ret;
        auto it = receivers.find(key);
        if (it == receivers.end()) {
            // This is a new long message.
            lmsg_receiver new_receiver;
            recv_ret = new_receiver.receive_chunk(chunk);
            if (recv_ret >= 0) {
                receivers.emplace(key, new_receiver);
                return recv_ret;    // Good to go.
            }
            return -5;  // Fatal.
        }
        else {
            // This is not a new message.
            recv_ret = (it->second).receive_chunk(chunk);
            if (recv_ret >= 0)
                return recv_ret;    // Good to go
            if (recv_ret == RECV_TIMEOUT_RETURN)
                return RECV_TIMEOUT_RETURN;  // Fatal.
            return -7;
        }
    }

    lmsg_receiver* get_receiver (const uint64_t& msg_id) {
        auto it = receivers.find(msg_id);
        if (it == receivers.end())
            return nullptr;
        return &(it->second);
    }

    void check_all (time_t now) {
        for (auto it = receivers.begin(); it != receivers.end(); ) {
            if (it->second.check_clear_timeout(now) != 0) {
                it = receivers.erase(it);
                if (trash.size() == LMSG_KEY_TRASH_SIZE) {
                    trash.erase(trash.begin(), 
                                trash.begin() + LMSG_KEY_TRASH_SIZE / 2);
                }
                trash.push_back(it->first);
            }
            else {
                ++ it;
            } 
        }
    }

    void delete_receiver (const uint64_t& msg_id) {
        receivers.erase(msg_id);
    }
};

class lmsg_sender {
    uint64_t msg_id;
    std::array<uint8_t, 8> msg_id_bytes;
    uint8_t chunk_size_mask;
    std::vector<std::vector<uint8_t>> send_chunks;
    time_t send_start_time;

public:
    lmsg_sender () {
        msg_id = 0;
        chunk_size_mask = DEFAULT_CHUNK_SIZE_MASK;
    }

    bool set_chunk_size_mask (uint8_t mask) {
        if (mask > CHUNK_SIZE_MASK_MAX) 
            return false;
        else 
            chunk_size_mask = mask;
        return true;
    }

    void gen_msg_id () {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint64_t> dis(0, UINT64_MAX);
        msg_id = dis(gen);
        msg_id_bytes = lc_utils::u64_to_bytes(msg_id);
    }

    const uint64_t get_msg_id () const {
        return msg_id;
    }

    bool presplit_raw_msg (const size_t& raw_bytes) {
        auto mask = chunk_size_mask;
        while (mask <= CHUNK_SIZE_MASK_MAX) {
            auto chunk_size = CHUNK_SIZE_MIN << mask;
            auto nchunks = raw_bytes / chunk_size + 1;
            if (nchunks > N_CHUNKS_MAX)
                ++ mask;
            else 
                break;
        }
        if (mask > CHUNK_SIZE_MASK_MAX)
            return false;
        if (mask != chunk_size_mask) 
            chunk_size_mask = mask;
        return true;
    }

    bool prepare_chunks_to_send (const std::vector<uint8_t>& raw_long_msg) {
        if (!presplit_raw_msg(raw_long_msg.size()))
            return false;

        send_chunks.clear();
        gen_msg_id();
        uint8_t chunk_header;

        auto size_mask = chunk_size_mask;
        auto send_msg_id = msg_id;
        auto send_msg_id_bytes = msg_id_bytes;

        auto chunk_size = CHUNK_SIZE_MIN << size_mask;
        auto nchunks = raw_long_msg.size() / chunk_size + 1;
        bool sn_dwidth = false;
        if (nchunks > SN_WIDTH_BOUNDARY) 
            sn_dwidth = true;
        chunk_header = size_mask << 1 | ((sn_dwidth) ? 0x01 : 0x00);
        auto last_chunk_size = raw_long_msg.size() % chunk_size;
        size_t chunk_vec_size = sizeof(msg_id) + 1 + ((sn_dwidth) ? 2 : 1) + 
                                chunk_size;
        size_t lchunk_vec_size = sizeof(msg_id) + 1 + ((sn_dwidth) ? 2 : 1) + 
                                 last_chunk_size;
        size_t raw_start, raw_end, offset;
        std::array<uint8_t, 2> sn_dbytes;
        auto raw_beg = raw_long_msg.begin();
        
        for (size_t i = 0; i < nchunks; ++ i) {
            std::vector<uint8_t> chunk_vec(0);
            raw_start = i * chunk_size;
            if (i != nchunks - 1) {
                raw_end = (i + 1) * chunk_size;
                chunk_vec.resize(chunk_vec_size);
            }
            else {
                raw_end = raw_long_msg.size();
                chunk_vec.resize(lchunk_vec_size);
            }
            offset = 0;
            std::copy(msg_id_bytes.begin(), msg_id_bytes.end(), 
                      chunk_vec.begin() + offset);
            offset += msg_id_bytes.size();
            chunk_vec[offset] = chunk_header;
            ++ offset;
            if (sn_dwidth) {
                sn_dbytes = lc_utils::u16_to_bytes(static_cast<uint16_t>(i));
                std::copy(sn_dbytes.begin(), sn_dbytes.end(), 
                          chunk_vec.begin() + offset);
                offset += 2;
            }
            else {
                chunk_vec[offset] = static_cast<uint8_t>(i);
                ++ offset;
            }
            std::copy(raw_beg + raw_start, raw_beg + raw_end, 
                      chunk_vec.begin() + offset);
            send_chunks.push_back(chunk_vec);
        }
        send_start_time = lc_utils::now_time();
        return true;
    }
    
    const std::vector<std::vector<uint8_t>>& get_send_chunks () const {
        return send_chunks;
    }

    void send_clear () {
        send_chunks.clear();
    }

    bool check_timeout (time_t now) {
        if (now - send_start_time > LMSG_ALIVE_SECS) {
            send_clear();
            return true;
        }
        return false;
    }

    
};

class lmsg_send_pool {
    std::unordered_map<uint64_t, lmsg_sender> senders;
    std::vector<uint64_t> trash;

public:
    lmsg_send_pool () {}

    lmsg_sender* get_sender (const uint64_t& msg_id) {
        auto it = senders.find(msg_id);
        if (it == senders.end())
            return nullptr;
        return &(it->second);
    }

    void add_sender (const lmsg_sender& sender) {
        senders.emplace(sender.get_msg_id(), sender);
    }

    void check_all (time_t now) {
        for (auto it = senders.begin(); it != senders.end(); ) {
            if (it->second.check_timeout(now)) 
                it = senders.erase(it);
            else 
                ++ it;
        }
    }

    void delete_sender (const uint64_t& msg_id) {
        senders.erase(msg_id);
    }
};