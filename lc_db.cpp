/*
 * Copyright (C) 2022-present Zhenrong WANG
 * This code is distributed under the license: MIT License
 * mailto: zhenrongwang@live.com | X/Twitter: wangzhr4
 */

#include "lc_db.hpp"
#include "lc_common.hpp"
#include <sqlite3.h>
#include <fstream>
#include <sstream>
#include <cstring>
#include <iostream>

namespace lichat_db {

database::database(const std::string& db_path) 
    : db_(nullptr), db_path_(db_path), is_open_(false) {
}

database::~database() {
    close();
}

bool database::open() {
    if (is_open_) {
        return true;
    }
    
    int rc = sqlite3_open(db_path_.c_str(), &db_);
    if (rc != SQLITE_OK) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db_) << std::endl;
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        return false;
    }
    
    // Enable foreign keys and WAL mode for better concurrency
    sqlite3_exec(db_, "PRAGMA foreign_keys = ON;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA journal_mode = WAL;", nullptr, nullptr, nullptr);
    
    is_open_ = true;
    return true;
}

void database::close() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
    is_open_ = false;
}

bool database::create_schema() {
    if (!is_open_) {
        return false;
    }
    
    const char* schema_sql = R"(
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            user_status INTEGER DEFAULT 0,
            bind_cif INTEGER DEFAULT 0,
            created_at INTEGER DEFAULT (strftime('%s', 'now')),
            last_login INTEGER DEFAULT 0
        );
        
        CREATE INDEX IF NOT EXISTS idx_username ON users(username);
        CREATE INDEX IF NOT EXISTS idx_email ON users(email);
    )";
    
    char* err_msg = nullptr;
    int rc = sqlite3_exec(db_, schema_sql, nullptr, nullptr, &err_msg);
    
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error creating schema: " << err_msg << std::endl;
        sqlite3_free(err_msg);
        return false;
    }
    
    return true;
}


bool database::user_exists_by_email(const std::string& email) {
    if (!is_open_) {
        return false;
    }
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT 1 FROM users WHERE email = ? LIMIT 1;";
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_STATIC);
    
    bool exists = (sqlite3_step(stmt) == SQLITE_ROW);
    
    sqlite3_finalize(stmt);
    return exists;
}

bool database::user_exists_by_username(const std::string& username) {
    if (!is_open_) {
        return false;
    }
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT 1 FROM users WHERE username = ? LIMIT 1;";
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    
    bool exists = (sqlite3_step(stmt) == SQLITE_ROW);
    
    sqlite3_finalize(stmt);
    return exists;
}

bool database::get_user_by_email(const std::string& email,
                                 std::string& username,
                                 std::array<char, crypto_pwhash_STRBYTES>& password_hash) {
    if (!is_open_) {
        return false;
    }
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT username, password_hash FROM users WHERE email = ?;";
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_STATIC);
    
    bool found = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* uname = sqlite3_column_text(stmt, 0);
        const void* passhash_blob = sqlite3_column_blob(stmt, 1);
        int passhash_len = sqlite3_column_bytes(stmt, 1);
        
        if (uname && passhash_blob && passhash_len == crypto_pwhash_STRBYTES) {
            username = std::string(reinterpret_cast<const char*>(uname));
            std::memcpy(password_hash.data(), passhash_blob, crypto_pwhash_STRBYTES);
            found = true;
        }
    }
    
    sqlite3_finalize(stmt);
    return found;
}

bool database::get_user_by_username(const std::string& username,
                                    std::string& email,
                                    std::array<char, crypto_pwhash_STRBYTES>& password_hash) {
    if (!is_open_) {
        return false;
    }
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT email, password_hash FROM users WHERE username = ?;";
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    
    bool found = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* uemail = sqlite3_column_text(stmt, 0);
        const void* passhash_blob = sqlite3_column_blob(stmt, 1);
        int passhash_len = sqlite3_column_bytes(stmt, 1);
        
        if (uemail && passhash_blob && passhash_len == crypto_pwhash_STRBYTES) {
            email = std::string(reinterpret_cast<const char*>(uemail));
            std::memcpy(password_hash.data(), passhash_blob, crypto_pwhash_STRBYTES);
            found = true;
        }
    }
    
    sqlite3_finalize(stmt);
    return found;
}

bool database::add_user(const std::string& email,
                       const std::string& username,
                       const std::array<char, crypto_pwhash_STRBYTES>& password_hash) {
    if (!is_open_) {
        return false;
    }
    
    sqlite3_stmt* stmt;
    const char* sql = "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?);";
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, password_hash.data(), crypto_pwhash_STRBYTES, SQLITE_STATIC);
    
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return (rc == SQLITE_DONE);
}

bool database::verify_password(const std::string& email,
                               const std::array<char, crypto_pwhash_STRBYTES>& password_hash) {
    if (!is_open_) {
        return false;
    }
    
    std::array<char, crypto_pwhash_STRBYTES> stored_hash;
    std::string username;
    
    if (!get_user_by_email(email, username, stored_hash)) {
        return false;
    }
    
    // Compare password hashes
    return (std::memcmp(password_hash.data(), stored_hash.data(), 
                       crypto_pwhash_STRBYTES) == 0);
}

bool database::update_user_status(const std::string& email, uint8_t status) {
    if (!is_open_) {
        return false;
    }
    
    sqlite3_stmt* stmt;
    const char* sql = "UPDATE users SET user_status = ? WHERE email = ?;";
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, status);
    sqlite3_bind_text(stmt, 2, email.c_str(), -1, SQLITE_STATIC);
    
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return (rc == SQLITE_DONE);
}

bool database::update_user_bind_cif(const std::string& email, uint64_t cif) {
    if (!is_open_) {
        return false;
    }
    
    sqlite3_stmt* stmt;
    const char* sql = "UPDATE users SET bind_cif = ? WHERE email = ?;";
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(cif));
    sqlite3_bind_text(stmt, 2, email.c_str(), -1, SQLITE_STATIC);
    
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return (rc == SQLITE_DONE);
}

size_t database::get_user_count() {
    if (!is_open_) {
        return 0;
    }
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT COUNT(*) FROM users;";
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return 0;
    }
    
    size_t count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = static_cast<size_t>(sqlite3_column_int64(stmt, 0));
    }
    
    sqlite3_finalize(stmt);
    return count;
}

std::string database::get_user_list_string(bool include_offline) {
    if (!is_open_) {
        return "";
    }
    
    sqlite3_stmt* stmt;
    const char* sql = include_offline 
        ? "SELECT username, user_status FROM users ORDER BY username;"
        : "SELECT username, user_status FROM users WHERE user_status = 1 ORDER BY username;";
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return "";
    }
    
    std::ostringstream oss;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* username = sqlite3_column_text(stmt, 0);
        int status = sqlite3_column_int(stmt, 1);
        
        if (username) {
            oss << reinterpret_cast<const char*>(username);
            if (status == 1) {
                oss << " (in)";
            }
            oss << "\n";
        }
    }
    
    sqlite3_finalize(stmt);
    return oss.str();
}

bool database::begin_transaction() {
    if (!is_open_) {
        return false;
    }
    return (sqlite3_exec(db_, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr) == SQLITE_OK);
}

bool database::commit_transaction() {
    if (!is_open_) {
        return false;
    }
    return (sqlite3_exec(db_, "COMMIT;", nullptr, nullptr, nullptr) == SQLITE_OK);
}

bool database::rollback_transaction() {
    if (!is_open_) {
        return false;
    }
    return (sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr) == SQLITE_OK);
}

} // namespace lichat_db

