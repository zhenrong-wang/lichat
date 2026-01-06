/*
 * Copyright (C) 2022-present Zhenrong WANG
 * This code is distributed under the license: MIT License
 * mailto: zhenrongwang@live.com | X/Twitter: wangzhr4
 */

#ifndef LC_DB_HPP
#define LC_DB_HPP

#include <string>
#include <memory>
#include <vector>
#include <array>
#include "lc_consts.hpp"

struct sqlite3;

namespace lichat_db {

/**
 * SQLite database abstraction for LiChat server
 * 
 * Provides thread-safe database operations for user management.
 * Uses SQLite for persistence with ACID transactions.
 */
class database {
private:
    sqlite3* db_;
    std::string db_path_;
    bool is_open_;
    
    // Disable copy
    database(const database&) = delete;
    database& operator=(const database&) = delete;
    
public:
    explicit database(const std::string& db_path);
    ~database();
    
    // Database lifecycle
    bool open();
    void close();
    bool is_open() const { return is_open_; }
    
    // Schema management
    bool create_schema();
    
    // User operations
    bool user_exists_by_email(const std::string& email);
    bool user_exists_by_username(const std::string& username);
    
    bool get_user_by_email(const std::string& email,
                          std::string& username,
                          std::array<char, crypto_pwhash_STRBYTES>& password_hash);
    
    bool get_user_by_username(const std::string& username,
                              std::string& email,
                              std::array<char, crypto_pwhash_STRBYTES>& password_hash);
    
    bool add_user(const std::string& email,
                  const std::string& username,
                  const std::array<char, crypto_pwhash_STRBYTES>& password_hash);
    
    bool verify_password(const std::string& email,
                        const std::array<char, crypto_pwhash_STRBYTES>& password_hash);
    
    bool update_user_status(const std::string& email, uint8_t status);
    bool update_user_bind_cif(const std::string& email, uint64_t cif);
    
    size_t get_user_count();
    
    // User list operations
    std::string get_user_list_string(bool include_offline = true);
    
    // Transaction support
    bool begin_transaction();
    bool commit_transaction();
    bool rollback_transaction();
};

} // namespace lichat_db

#endif // LC_DB_HPP

