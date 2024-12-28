/*
 * Copyright (C) 2022-present Zhenrong WANG
 * This code is distributed under the license: MIT License
 * mailto: zhenrongwang@live.com | X/Twitter: wangzhr4
 */

#include "lc_common.hpp"
#include <atomic>
#include <random>
#include <stddef.h>
#include <unordered_map>

constexpr size_t CHUNK_SIZE_MIN = 64;

constexpr size_t  SN_WIDTH_BOUNDARY       = 256;
constexpr size_t  N_CHUNKS_MAX            = 65536;
constexpr size_t  N_CHUNKS_MID            = 256;
constexpr uint8_t DEFAULT_CHUNK_SIZE_MASK = 0x05; // 2048 byte
constexpr uint8_t CHUNK_SIZE_MASK_MAX     = 0x09; // 0 ~ 9, 64byte - 32KB

// Currently, this protocal is for messaging, not for large file
// transfer, so we set the time window to a short period.
// In the future, if we plan to support large file transfer,
// We would adjust this time window.
// Because the send/recv of long message is blocking, if this window
// is too big, performance would be severly affected.
// Maybe we need to consider threading for large file transfer. But that
// would need efforts at both server side and client side.
// To make it simple for now, we set the time window to 10.
constexpr size_t TIME_WINDOW_SECS = 10;

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

struct recv_utils {
    uint64_t               msg_id;
    std::array<uint8_t, 8> msg_id_bytes;
    bool                   last_chunk_received;
    bool                   recv_sn_dwidth;
    uint8_t                recv_header;
    size_t                 recv_chunk_size;
    size_t                 recv_total_chunks;
    std::vector<uint8_t>   recv_bitmap;
    time_t                 recv_start_time;

    recv_utils()
    {
        msg_id              = 0;
        last_chunk_received = false;
        recv_sn_dwidth      = false;
        recv_header         = 0x00;
        recv_chunk_size     = 0;
        recv_total_chunks   = 0;
    }

    bool is_chunk_received(uint16_t chunk_sn)
    {
        uint16_t byte = chunk_sn / 8;
        uint8_t  bit  = chunk_sn % 8;
        return ((recv_bitmap[byte] & (0x80 >> bit)) != 0);
    }

    void record_chunk(uint16_t chunk_sn)
    {
        uint16_t byte = chunk_sn / 8;
        uint8_t  bit  = chunk_sn % 8;
        recv_bitmap[byte] |= (0x80 >> bit);
    }
};

struct send_utils {
    uint64_t               msg_id;
    std::array<uint8_t, 8> msg_id_bytes;
    uint8_t                chunk_size_mask;

    send_utils()
    {
        msg_id          = 0;
        chunk_size_mask = DEFAULT_CHUNK_SIZE_MASK;
    }

    send_utils(uint8_t mask)
    {
        msg_id = 0;
        if (mask > CHUNK_SIZE_MASK_MAX)
            chunk_size_mask = DEFAULT_CHUNK_SIZE_MASK;
        else
            chunk_size_mask = mask;
    }

    bool set_chunk_size_mask(uint8_t mask)
    {
        if (mask > CHUNK_SIZE_MASK_MAX)
            return false;
        else
            chunk_size_mask = mask;
        return true;
    }

    void gen_msg_id()
    {
        std::random_device                      rd;
        std::mt19937                            gen(rd());
        std::uniform_int_distribution<uint64_t> dis(0, UINT64_MAX);
        msg_id       = dis(gen);
        msg_id_bytes = lc_utils::u64_to_bytes(msg_id);
    }

    bool presplit_raw_msg(const size_t& raw_bytes)
    {
        auto mask = chunk_size_mask;
        while (mask <= CHUNK_SIZE_MASK_MAX) {
            auto chunk_size = CHUNK_SIZE_MIN << mask;
            auto nchunks    = raw_bytes / chunk_size + 1;
            if (nchunks > N_CHUNKS_MAX)
                ++mask;
            else
                break;
        }
        if (mask > CHUNK_SIZE_MASK_MAX)
            return false;
        if (mask != chunk_size_mask)
            chunk_size_mask = mask;
        return true;
    }
};

class long_msg {
    // For sending
    send_utils                        send_mgr;
    std::vector<std::vector<uint8_t>> send_chunks;

    // For receiving
    recv_utils                                         recv_mgr;
    std::unordered_map<uint16_t, std::vector<uint8_t>> recv_chunks;

    // The serial number should be 0~65535
    std::array<uint8_t, 2> sn_to_bytes(uint16_t num)
    {
        std::array<uint8_t, 2> ret;
        ret[0] = static_cast<uint8_t>(num & (0xFF));
        ret[1] = static_cast<uint8_t>((num >> 8) & (0xFF));
        return ret;
    }

    uint16_t bytes_to_sn(std::array<uint8_t, 2> arr)
    {
        return static_cast<uint16_t>(arr[0]) | static_cast<uint16_t>(arr[1] << 8);
    }

public:
    long_msg() : send_mgr(send_utils()), recv_mgr(recv_utils()) {}

    long_msg(uint8_t mask) : send_mgr(send_utils(mask)), recv_mgr(recv_utils()) {}

    bool set_send_chunk_mask(const uint8_t mask)
    {
        return send_mgr.set_chunk_size_mask(mask);
    }

    const std::vector<std::vector<uint8_t>>& get_send_chunks() const
    {
        return send_chunks;
    }

    const std::unordered_map<uint16_t, std::vector<uint8_t>>& get_recv_chunks() const
    {
        return recv_chunks;
    }

    bool prepare_chunks_to_send(const std::vector<uint8_t>& raw_long_msg)
    {
        if (!send_mgr.presplit_raw_msg(raw_long_msg.size()))
            return false;

        send_chunks.clear();
        send_mgr.gen_msg_id();
        uint8_t chunk_header;

        auto size_mask    = send_mgr.chunk_size_mask;
        auto msg_id       = send_mgr.msg_id;
        auto msg_id_bytes = send_mgr.msg_id_bytes;

        auto chunk_size = CHUNK_SIZE_MIN << size_mask;
        auto nchunks    = raw_long_msg.size() / chunk_size + 1;
        bool sn_dwidth  = false;
        if (nchunks > SN_WIDTH_BOUNDARY)
            sn_dwidth = true;
        chunk_header                           = size_mask << 1 | ((sn_dwidth) ? 0x01 : 0x00);
        auto                   last_chunk_size = raw_long_msg.size() % chunk_size;
        size_t                 chunk_vec_size  = sizeof(msg_id) + 1 + ((sn_dwidth) ? 2 : 1) + chunk_size;
        size_t                 lchunk_vec_size = sizeof(msg_id) + 1 + ((sn_dwidth) ? 2 : 1) + last_chunk_size;
        size_t                 raw_start, raw_end, offset;
        std::array<uint8_t, 2> sn_dbytes;
        auto                   raw_beg = raw_long_msg.begin();

        for (size_t i = 0; i < nchunks; ++i) {
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
            std::copy(msg_id_bytes.begin(), msg_id_bytes.end(), chunk_vec.begin() + offset);
            offset += msg_id_bytes.size();
            chunk_vec[offset] = chunk_header;
            ++offset;
            if (sn_dwidth) {
                sn_dbytes = sn_to_bytes(static_cast<uint8_t>(i));
                std::copy(sn_dbytes.begin(), sn_dbytes.end(), chunk_vec.begin() + offset);
                offset += 2;
            }
            else {
                chunk_vec[offset] = static_cast<uint8_t>(i);
                ++offset;
            }
            std::copy(raw_beg + raw_start, raw_beg + raw_end, chunk_vec.begin() + offset);
            send_chunks.push_back(chunk_vec);
        }
        return true;
    }

    int receive_chunk(const std::vector<uint8_t>& raw_chunk)
    {
        if (raw_chunk.size() < sizeof(uint64_t) + 2)
            return -1;
        std::array<uint8_t, 8> raw_msg_id_bytes;
        uint64_t               raw_msg_id;
        auto                   raw_beg = raw_chunk.begin();
        size_t                 offset  = 0;
        std::copy(raw_beg, raw_beg + 8, raw_msg_id_bytes.begin());
        raw_msg_id = lc_utils::bytes_to_u64(raw_msg_id_bytes);
        if (recv_chunks.empty()) {
            (recv_mgr.recv_bitmap).clear(); // Prepare the bitmap.
            recv_mgr.msg_id = raw_msg_id;   // Record the message id.
        }
        else {
            if (raw_msg_id != recv_mgr.msg_id) // Compare the message id.
                return -3;
        }
        offset += 8;
        auto raw_header = raw_chunk[offset];
        if (recv_chunks.empty()) {
            recv_mgr.recv_start_time   = lc_utils::now_time();
            recv_mgr.recv_total_chunks = 0;
            uint8_t raw_mask           = raw_header >> 1;
            if (raw_mask > CHUNK_SIZE_MASK_MAX)
                return -5; // Invalid mask.
            auto raw_chunk_size = CHUNK_SIZE_MIN << raw_mask;
            bool raw_sn_dwidth  = (raw_header & static_cast<uint8_t>(0x01));
            if (raw_sn_dwidth && (offset + 2 > raw_chunk.size()))
                return -7; // Invalid length.
            if (raw_sn_dwidth)
                (recv_mgr.recv_bitmap).resize(N_CHUNKS_MAX);
            else
                (recv_mgr.recv_bitmap).resize(N_CHUNKS_MID);
            // Record the header.
            recv_mgr.recv_header     = raw_header;
            recv_mgr.recv_sn_dwidth  = raw_sn_dwidth;
            recv_mgr.recv_chunk_size = raw_chunk_size;
        }
        else {
            if (raw_header != recv_mgr.recv_header)
                return -9;
        }
        ++offset;
        uint16_t raw_chunk_sn;
        if (recv_mgr.recv_sn_dwidth) {
            std::array<uint8_t, 2> chunk_sn_bytes;
            std::copy(raw_beg + offset, raw_beg + offset + 2, chunk_sn_bytes.begin());
            raw_chunk_sn = bytes_to_sn(chunk_sn_bytes);
            offset += 2;
        }
        else {
            raw_chunk_sn = static_cast<uint16_t>(raw_beg[offset]);
            ++offset;
        }
        if (recv_mgr.is_chunk_received(raw_chunk_sn))
            return 1;
        // Now copy the message body.
        std::vector<uint8_t> chunk_msg(raw_chunk.size() - offset);
        std::copy(raw_beg + offset, raw_chunk.end(), chunk_msg.begin());
        recv_chunks.emplace(raw_chunk_sn, chunk_msg);
        recv_mgr.record_chunk(raw_chunk_sn);
        size_t raw_chunk_msg_size = raw_chunk.size() - offset;
        if (raw_chunk_msg_size != recv_mgr.recv_chunk_size) {
            // recv_total_chunks = 0 ~ 65536
            recv_mgr.recv_total_chunks = static_cast<size_t>(raw_chunk_sn) + 1;
            return 3; // Received the last chunk;
        }
        return 0; // Received a normal chunk
    }

    std::vector<uint16_t> check_missing_chunks()
    {
        std::vector<uint16_t> ret;
        auto                  max_byte = recv_mgr.recv_total_chunks / 8;
        auto                  last_bit = recv_mgr.recv_total_chunks % 8;
        for (size_t i = 0; i < max_byte; ++i) {
            if (recv_mgr.recv_bitmap[i] == 0xFF)
                continue;
            auto byte = recv_mgr.recv_bitmap[i];
            for (size_t j = 0; j < 8; ++j) {
                if ((byte & (static_cast<uint8_t>(0x80) >> j)) == 0)
                    ret.push_back(static_cast<uint16_t>(i * 8 + j));
            }
        }
        auto last_byte = recv_mgr.recv_bitmap[max_byte];
        for (size_t j = 0; j < last_bit; ++j) {
            if ((last_byte & (static_cast<uint8_t>(0x80) >> j)) == 0)
                ret.push_back(static_cast<uint16_t>(max_byte * 8 + j));
        }
        return ret;
    }
};