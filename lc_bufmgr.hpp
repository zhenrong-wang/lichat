#ifndef LC_BUFMGR_HPP
#define LC_BUFMGR_HPP

#include "lc_consts.hpp"
#include <array>
#include <iostream>
#include <cstring>
#include "sodium.h"

struct msg_buffer {
    std::array<uint8_t, BUFF_SIZE> recv_raw_buffer;
    ssize_t recv_raw_bytes;

    // A buffer to handle aes decryption
    std::array<uint8_t, BUFF_SIZE> recv_aes_buffer;
    ssize_t recv_aes_bytes;

    std::array<uint8_t, BUFF_SIZE> send_aes_buffer;
    ssize_t send_aes_bytes;

    // A buffer to send aes_encrypted messages
    std::array<uint8_t, BUFF_SIZE> send_buffer;
    ssize_t send_bytes;

    msg_buffer() : recv_raw_bytes(0), recv_aes_bytes(0), send_aes_bytes(0), send_bytes(0) {}

    static ssize_t size_to_clear(ssize_t bytes) {
        if(bytes < 0 || bytes >= BUFF_SIZE)
            return BUFF_SIZE;
        return bytes;
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

    void clear_buffer() {
        std::memset(recv_raw_buffer.data(), 0, size_to_clear(recv_raw_bytes));
        std::memset(recv_aes_buffer.data(), 0, size_to_clear(recv_aes_bytes));
        std::memset(send_aes_buffer.data(), 0, size_to_clear(send_aes_bytes));
        std::memset(send_buffer.data(), 0, size_to_clear(send_bytes));
        recv_raw_bytes = 0;
        recv_aes_bytes = 0;
        send_aes_bytes = 0;
        send_bytes = 0;
    }
    bool is_recv_empty() const {
        return (recv_raw_bytes == 0);
    }
    bool recved_insuff_bytes(const size_t min_bytes) const {
        return (recv_raw_bytes < min_bytes);
    }
    bool recved_overflow() const {
        return (recv_raw_bytes == recv_raw_buffer.size());
    }
};

#endif