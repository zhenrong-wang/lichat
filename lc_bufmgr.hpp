/*
 * Copyright (C) 2022-present Zhenrong WANG
 * This code is distributed under the license: MIT License
 * mailto: zhenrongwang@live.com | X/Twitter: wangzhr4
 */

#ifndef LC_BUFMGR_HPP
#define LC_BUFMGR_HPP

// Project includes
#include "lc_common.hpp"
#include "lc_consts.hpp"

// Third-party includes
#include <sodium.h>

// Platform includes
#ifdef _WIN32
#    ifdef _WIN64
typedef signed long long ssize_t;
#    else
typedef signed long ssize_t;
#    endif
#else
#    include <sys/types.h>
#endif

// C++ std lib includes
#include <array>
#include <cstring>
#include <iostream>

struct msg_buffer {
    std::array<uint8_t, BUFF_BYTES> recv_raw_buffer;
    ssize_t                         recv_raw_bytes;

    // A buffer to handle aes decryption
    std::array<uint8_t, BUFF_BYTES> recv_aes_buffer;
    ssize_t                         recv_aes_bytes;

    std::array<uint8_t, BUFF_BYTES> send_aes_buffer;
    ssize_t                         send_aes_bytes;

    // A buffer to send aes_encrypted messages
    std::array<uint8_t, BUFF_BYTES> send_buffer;
    ssize_t                         send_bytes;

    msg_buffer() : recv_raw_bytes(0), recv_aes_bytes(0), send_aes_bytes(0), send_bytes(0) {}

    static ssize_t size_to_clear(ssize_t bytes)
    {
        if (bytes < 0 || bytes >= BUFF_BYTES)
            return BUFF_BYTES;
        return bytes;
    }

    void clear_buffer()
    {
        std::memset(recv_raw_buffer.data(), 0, size_to_clear(recv_raw_bytes));
        std::memset(recv_aes_buffer.data(), 0, size_to_clear(recv_aes_bytes));
        std::memset(send_aes_buffer.data(), 0, size_to_clear(send_aes_bytes));
        std::memset(send_buffer.data(), 0, size_to_clear(send_bytes));
        recv_raw_bytes = 0;
        recv_aes_bytes = 0;
        send_aes_bytes = 0;
        send_bytes     = 0;
    }
    bool is_recv_empty() const
    {
        return (recv_raw_bytes == 0);
    }
    bool recved_insuff_bytes(const size_t min_bytes) const
    {
        return (recv_raw_bytes < min_bytes);
    }
    bool recved_overflow() const
    {
        return (recv_raw_bytes == recv_raw_buffer.size());
    }
};

#endif