/*
 * Copyright (C) 2022-present Zhenrong WANG
 * This code is distributed under the license: MIT License
 * mailto: zhenrongwang@live.com | X/Twitter: wangzhr4
 */

/* CONSTANTS used by this project. */

#ifndef LC_CONSTS_HPP
#define LC_CONSTS_HPP

#include <iostream>
#include <array>
#include "sodium.h"

// Critical bytes
constexpr uint8_t CID_BYTES = 8;
constexpr uint8_t SID_BYTES = 8;
constexpr uint8_t CIF_BYTES = 8;

// User login related
constexpr ssize_t ULOGIN_MIN_BYTES = 4; // uname or uemail.
constexpr ssize_t UNAME_MAX_BYTES = 32;
constexpr ssize_t UEMAIL_MAX_BYTES = 256;
constexpr ssize_t PASSWORD_MAX_BYTES = 64;
constexpr ssize_t PASSWORD_MIN_BYTES = 4;
constexpr ssize_t SPECIAL_CHAR_NUM = 26;
constexpr std::array<char, SPECIAL_CHAR_NUM> special_chars = {
    '~', '!', '@', '#', '$', '%', '^', '&', '(', ')', '{', '}', '[',
    ']', '-', '_', '=', '+', ';', ':', ',', '.', '<', '>', '/', '|'
};
constexpr size_t CLIENT_INPUT_RETRY = 3;

// Addr related
constexpr char DEFAULT_SERVER_ADDR[] = "127.0.0.1";
constexpr uint16_t DEFAULT_SERVER_PORT = 8081;

constexpr uint8_t ok[] = {'O', 'K'};

// Buffer size
constexpr ssize_t BUFF_BYTES = 65536;
constexpr ssize_t INPUT_BUFF_BYTES = BUFF_BYTES - 256;

// Err code has 1-byte header + 6-byte body
constexpr size_t ERR_CODE_BYTES = 6;

// Minimal bytes
constexpr ssize_t SERVER_RECV_MIN_BYTES = 1 + CID_BYTES + 
                                         crypto_box_PUBLICKEYBYTES;
constexpr ssize_t CLIENT_RECV_MIN_BYTES = 1 + ERR_CODE_BYTES;

constexpr uint8_t server_ff_failed[ERR_CODE_BYTES + 1] = 
    {0xFF, 'F', 'A', 'I', 'L', 'E', 'D'};
constexpr uint8_t server_fe_keyerr[ERR_CODE_BYTES + 1] = 
    {0xFE, 'K', 'E', 'Y', 'E', 'R', 'R'};
constexpr uint8_t server_fd_msgerr[ERR_CODE_BYTES + 1] = 
    {0xFD, 'M', 'S', 'G', 'E', 'R', 'R'};
constexpr uint8_t server_fc_siderr[ERR_CODE_BYTES + 1] = 
    {0xFC, 'S', 'I', 'D', 'E', 'R', 'R'};

constexpr uint8_t client_ff_timout[ERR_CODE_BYTES] = 
    {'T', 'I', 'M', 'O', 'U', 'T'};
constexpr uint8_t client_fe_keyerr[ERR_CODE_BYTES] = 
    {'K', 'E', 'Y', 'E', 'R', 'R'};
constexpr uint8_t client_fd_msgerr[ERR_CODE_BYTES] = 
    {'M', 'S', 'G', 'E', 'R', 'R'};

// The default key dir
constexpr char default_key_dir[] = "./";

// The default user db path
constexpr char default_user_db_path[] = "./lichat_signed_users.db";

// Heartbeating related.
constexpr time_t DEFAULT_HEARTBEAT_INTERVAL_SECS = 15;
constexpr time_t HEARTBEAT_TIMEOUT_SECS = 60;
constexpr size_t HEARTBEAT_THREAD_SLEEP_MS = 500;
constexpr size_t HEARTBEAT_BYTES = 1 + crypto_sign_BYTES + CIF_BYTES;

// Every 2 minutes, the server would check all the connections.
constexpr time_t SERVER_CONNS_CHECK_SECS = HEARTBEAT_TIMEOUT_SECS * 2;

// A goodbye packet is a special heartbeating packet with an extra byte '!'
constexpr size_t GOODBYE_BYTES = HEARTBEAT_BYTES + 1;

// Handshake related
constexpr time_t HANDSHAKE_TIMEOUT_SECS = 15;

// Server receive wait
constexpr time_t SERVER_RECV_WAIT_SECS = 10;


constexpr size_t LMSG_KEY_TRASH_SIZE = 65536;

// Server user_db header
const std::string user_db_header = "UEMAIL,UNAME,PASSHASH\n";

// Some useful strings.
constexpr char fatal_error[] = "Server internal fatal error.\n";
constexpr char restart_handshake[] = "Session failed. Restart handshake.\n";
constexpr char main_menu[] = "1. signup\n2. signin\n\
Please choose (1 | 2) or (signup | signin): ";
constexpr char choose_login[] = "1. email\n2. username\nPlease choose a login \
type (1 | 2) or (email | username): ";
constexpr char input_email[] =    "E-mail: ";
constexpr char input_username[] = "\nUsername format:\n1) 4-64 ascii chars.\n\
2) Only a-z A-Z 0-9 - _ are allowed.\n\nUsername: ";
constexpr char input_password[] = "\nPassword format:\n1) 4-32 ascii chars.\n\
2) Must contain at least 3 types, must contain special char(s):\n\
   [lowercase]: a-z\n   [UPPERCASE]: A-Z\n   [#numbers#]: 0-9\n\
   [special_c]: ~!@#$%^&(){}[]-_=+;:,.<>/|\n\nPassword: ";
constexpr char retype_password[] = "Re-type to confirm: ";
constexpr char connection_reset[] = "This connection has been reset.\n\n";
constexpr char s_signout[5] = {'[', '(', '!', ')', ']'};
constexpr char signout_close[] = "[(!)] You've signed in on another client.";

#endif