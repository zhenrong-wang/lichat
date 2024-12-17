#ifndef LC_CONSTS_HPP
#define LC_CONSTS_HPP

#include <iostream>
#include <array>
#include "sodium.h"

constexpr uint8_t CID_BYTES = 8;
constexpr uint8_t SID_BYTES = 8;
constexpr uint8_t CIF_BYTES = 8;

constexpr size_t ULOGIN_MIN_BYTES = 4; // uname or uemail.
constexpr size_t UNAME_MAX_BYTES = 64;
constexpr size_t UEMAIL_MAX_BYTES = 256;

constexpr size_t PASSWORD_MAX_BYTES = 64;
constexpr size_t PASSWORD_MIN_BYTES = 4;

constexpr char DEFAULT_SERVER_ADDR[] = "127.0.0.1";
constexpr uint16_t DEFAULT_SERVER_PORT = 8081;

constexpr size_t BUFF_SIZE = 4096;
constexpr size_t INPUT_BUFF_SIZE = BUFF_SIZE - 128;

constexpr size_t ERR_CODE_BYTES = 6;

constexpr size_t SERVER_RECV_MIN_BYTES = 1 + CID_BYTES + crypto_box_PUBLICKEYBYTES;
constexpr size_t CLIENT_RECV_MIN_BYTES = 1 + ERR_CODE_BYTES;

constexpr size_t SPECIAL_CHAR_NUM = 26;

constexpr size_t CLIENT_INPUT_RETRY = 3;

constexpr std::array<char, SPECIAL_CHAR_NUM> special_chars = {
    '~', '!', '@', '#', '$', '%', '^', '&', '(', ')', '{', '}', '[',
    ']', '-', '_', '=', '+', ';', ':', ',', '.', '<', '>', '/', '|'
};

constexpr uint8_t server_ff_failed[ERR_CODE_BYTES + 1] = {0xFF, 'F', 'A', 'I', 'L', 'E', 'D'};
constexpr uint8_t server_ef_keyerr[ERR_CODE_BYTES + 1] = {0xEF, 'K', 'E', 'Y', 'E', 'R', 'R'};
constexpr uint8_t server_df_msgerr[ERR_CODE_BYTES + 1] = {0xDF, 'M', 'S', 'G', 'E', 'R', 'R'};
constexpr uint8_t server_cf_siderr[ERR_CODE_BYTES + 1] = {0xCF, 'S', 'I', 'D', 'E', 'R', 'R'};

constexpr uint8_t ok[] = {'O', 'K'};
constexpr uint8_t yes[] = {'y', 'e', 's'};
constexpr uint8_t no[] = {'n', 'o'};

constexpr uint8_t client_ff_timout[ERR_CODE_BYTES] = {'T', 'I', 'M', 'O', 'U', 'T'};
constexpr uint8_t client_ef_keyerr[ERR_CODE_BYTES] = {'K', 'E', 'Y', 'E', 'R', 'R'};
constexpr uint8_t client_df_msgerr[ERR_CODE_BYTES] = {'M', 'S', 'G', 'E', 'R', 'R'};

constexpr char default_key_dir[] = "./";

constexpr char server_bcast_header[] = "[SYSTEM_BROADCASTING]:";
constexpr char server_internal_fatal[] = "Server internal fatal error.\n";
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
constexpr char option_error[] = "Option error, please input 1 or 2\n";
constexpr char user_uid_exist[] = "User already exists.\n";
constexpr char user_uid_error[] = "User does not exist.\n";
constexpr char password_error[] = "Password doesn't match.\n";
constexpr char signup_ok[] = "[SYSTEM_WELCOME] You've signed up and signed in.\n\
[SYSTEM_WELCOME] Send ~:q! to sign out.\n\
[SYSTEM_WELCOME] Send ~-@uid: to tag another user.\n\
[SYSTEM_WELCOME] Send ~->uid: to send private messages to another user.\n\n";
constexpr char signin_ok[] = "[SYSTEM_WELCOME] You've signed in.\n\
[SYSTEM_WELCOME] Send ~:q! to sign out.\n\
[SYSTEM_WELCOME] Send ~-@uid: to tag another user.\n\
[SYSTEM_WELCOME] Send ~->uid: to send private messages to another user.\n\n";
constexpr char password_not_complex[] = "the password is not complex enough.\n";
constexpr char signed_out[] = "[SYSTEM] You have signed out.\n";
constexpr char user_already_signin[] = "User already signed in at client: ";
constexpr char user_resign_in[] = "This signin would quit that client, are you sure? (yes | no)\n";
constexpr char another_sign_warn[] = "[SYSTEM_WARN] Another client is trying to sign in your uid!\n";
constexpr char not_yes_or_no[] = "Option error, please send either `yes` or `no`\n";
constexpr char option_denied[] = "You sent no. Nothing changed.\n";
constexpr char client_switched[] = "You've re-signed in on another client. Signed out here.\n";
constexpr char connection_reset[] = "This connection has been reset.\n\n";
constexpr char cannot_at_or_to_user[] = "[SYSTEM] Target user not signed in.\n";
constexpr char cannot_at_or_to_self[] = "[SYSTEM] You cannot tag or send privated messages to yourself.\n";
constexpr char been_tagged[] = "[SYSTEM_NOTIFY] You've been tagged!";
constexpr char private_msg_recved[] = "[SYSTEM_NOTIFY] You've received a private message!";
constexpr char private_msg_sent[] = "[SYSTEM_INFO] You've sent a private message!";
constexpr char auto_signout[] = "You've been signed in on another session. Signed out here.";
constexpr char signed_in[] = " signed in!";
constexpr size_t MSG_ATTR_LEN = 3;
constexpr char to_user[MSG_ATTR_LEN] = {'~', '-', '>'};
constexpr char tag_user[MSG_ATTR_LEN] = {'~', '-', '@'};
constexpr char user_delim = ':';

constexpr size_t WIN_HEIGHT_MIN = 16;
constexpr size_t WIN_WIDTH_MIN = 48;
constexpr size_t SIDE_WIN_WIDTH = 16;
constexpr size_t BOTTOM_HEIGHT = 8;

#endif