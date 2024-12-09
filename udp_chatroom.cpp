// This is the *simplest* UDP (Message based) echo server in C++ for learning
// Originally written by Zhenrong WANG (zhenrongwang@live.com | X/Twitter: @wangzhr4)
// Prerequisites: libsodium. You need to install it before compiling this code
// Compile: g++ udp_chatroom.cpp -lsodium

#include <iostream>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <vector>
#include <sodium.h>     // For libsodium
#include <cstring>      // For C string 
#include <algorithm>    // For std::find_if
#include <sstream>      // For stringstream
#include <unordered_map>
#include <chrono>
#include <ctime>
#include <fstream>
#include <regex>
#include <random>

constexpr uint8_t CID_BYTES = 8;
constexpr uint8_t SID_BYTES = 8;
constexpr uint8_t CIF_BYTES = 8;

constexpr size_t ULOGIN_MIN_BYTES = 4; // uname or uemail.
constexpr size_t UNAME_MAX_BYTES = 64;
constexpr size_t UEMAIL_MAX_BYTES = 256;

constexpr size_t PASSWORD_MAX_BYTES = 64;
constexpr size_t PASSWORD_MIN_BYTES = 4;
constexpr uint16_t DEFAULT_PORT = 8081;
constexpr size_t BUFF_SIZE = 4096;
constexpr size_t ERR_CODE_BYTES = 6;
constexpr size_t SERVER_MSG_PUBBYTES_MAX = 64;

constexpr size_t SPECIAL_CHAR_NUM = 26;

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

constexpr char server_internal_fatal[] = "Server internal fatal error.\n";
constexpr char restart_handshake[] = "Session failed. Restart handshake.\n";
constexpr char main_menu[] = "1. signup\n2. signin\nPlease choose (1 | 2): ";
constexpr char input_username[] = "Username: ";
constexpr char input_password[] = "Password: ";
constexpr char option_error[] = "Option error, please input 1 or 2\n";
constexpr char user_uid_exist[] = "User already exists.\n";
constexpr char user_uid_error[] = "User does not exist.\n";
constexpr char password_error[] = "Password doesn't match.\n";
constexpr char invalid_uid_fmt[] = "Invalid uid format, rules to follow:\n\
    4-64 ascii chars.\n\
    a-z, A-Z, numbers, and/or hyphen-.\n";
constexpr char invalid_uid_len[] = "Invalid uid length: 4-64\n";
constexpr char invalid_pass_fmt[] = "Invalid password format, rules to follow:\n\
    4-32 ascii chars.\n\
    a-z, A-Z, numbers, and special chars, no spaces.\n\
    * Must contains at least 3 out of 4 types above.\n";
constexpr char invalid_pass[] = "Not a valid password string.\n";
constexpr char invalid_pass_len[] = "Invalid password length: 4-32\n";
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
constexpr size_t MSG_ATTR_LEN = 3;
constexpr char to_user[MSG_ATTR_LEN] = {'~', '-', '>'};
constexpr char tag_user[MSG_ATTR_LEN] = {'~', '-', '@'};
constexpr char user_delim = ':';

class ctx_user_bind_buffer {
    std::string user_uid;
    uint64_t prev_key;
    bool is_set;
public:
    ctx_user_bind_buffer() : prev_key(0), is_set(false) {
        user_uid.clear();
    }
    void set_bind_buffer(const std::string& uid, const uint64_t& key) {
        user_uid = uid;
        prev_key = key;
        is_set = true;
    }
    void unset_bind_buffer(void) {
        user_uid.clear();
        prev_key = 0;
        is_set = false;
    }
    const bool is_set_buffer(void) const {
        return is_set;
    }
    const std::string& get_user_uid() {
        return user_uid;
    }
    const uint64_t& get_prev_key() const {
        return prev_key;
    }
};

struct msg_attr {
    uint8_t msg_attr_mask;  // 00 - public & untagged;
                            // 01 - public but tagged (target_uid and target_ctx_idx valid)
                            // 02 - private (target_uid and target_ctx_idx valid)
    std::string target_uid;
    ssize_t target_ctx_idx;
    bool is_set;

    void msg_attr_reset() {
        msg_attr_mask = 0;
        target_uid.clear();
        target_ctx_idx = -1;
        is_set = false;
    }
};

class curve25519_key_mgr {
    std::array<uint8_t, crypto_box_PUBLICKEYBYTES> public_key;
    std::array<uint8_t, crypto_box_SECRETKEYBYTES> secret_key;
    bool is_empty;
public:
    curve25519_key_mgr() : is_empty(true) {}
    
    static int read_curve25519_key_file(const std::string& file_path, std::vector<uint8_t>& content, const std::streamsize& expected_size) {
        if(expected_size != crypto_box_PUBLICKEYBYTES && expected_size != crypto_box_SECRETKEYBYTES)
            return -1; // function call error
        std::ifstream file(file_path, std::ios::in | std::ios::binary | std::ios::ate);
        if(!file.is_open())
            return 1; // file open error
        std::streamsize size = file.tellg();
        if(size != expected_size) {
            file.close();
            return 3; // file size error
        }
        file.seekg(0, std::ios::beg);
        content.resize(size);
        if(!file.read(reinterpret_cast<char *>(content.data()), size)) {
            file.close();
            return 5; // file read error
        }
        file.close();
        return 0; // This doesn't mean the keys are valid, only format is correct.
    }

    // This is a force operation, no status check
    int load_local_key_files(std::string& pub_key_file, std::string& priv_key_file) {
        std::vector<uint8_t> public_key_vec, secret_key_vec;
        auto ret = read_curve25519_key_file(pub_key_file, public_key_vec, crypto_box_PUBLICKEYBYTES);
        if(ret != 0)
            return ret; // 1, 3, 5
        ret = read_curve25519_key_file(priv_key_file, secret_key_vec, crypto_box_SECRETKEYBYTES);
        if(ret != 0)
            return -ret; // -1, -3, -5
        uint8_t random_msg[32];
        uint8_t enc_msg[crypto_box_SEALBYTES + sizeof(random_msg)];
        uint8_t dec_msg[sizeof(random_msg)];
        randombytes_buf(random_msg, sizeof(random_msg));
        crypto_box_seal(enc_msg, random_msg, sizeof(random_msg), public_key_vec.data());
        if(crypto_box_seal_open(dec_msg, enc_msg, sizeof(enc_msg), public_key_vec.data(), secret_key_vec.data()) != 0)
            return 7;
        if(std::memcmp(random_msg, dec_msg, sizeof(random_msg)) == 0) {
            std::copy(public_key_vec.begin(), public_key_vec.end(), public_key.begin());
            std::copy(secret_key_vec.begin(), secret_key_vec.end(), secret_key.begin());
            is_empty = false;
            return 0;
        }
        return 7; // key doesn't match
    }

    // This is a force operation, no status check.
    int gen_key_save_to_local(std::string& pub_key_file_path, std::string& sec_key_file_path) {
        std::ofstream out_pub_key(pub_key_file_path, std::ios::binary);
        if(!out_pub_key.is_open())
            return 1;
        std::ofstream out_sec_key(sec_key_file_path, std::ios::binary);
        if(!out_sec_key.is_open()) {
            out_pub_key.close();
            return -1;
        }
        uint8_t gen_public_key[crypto_box_PUBLICKEYBYTES];
        uint8_t gen_secret_key[crypto_box_SECRETKEYBYTES];
        crypto_box_keypair(gen_public_key, gen_secret_key);
        std::copy(std::begin(gen_public_key), std::end(gen_public_key), public_key.begin());
        std::copy(std::begin(gen_secret_key), std::end(gen_secret_key), secret_key.begin());
        is_empty = false;
        out_pub_key.write(reinterpret_cast<const char *>(public_key.data()), public_key.size());
        out_sec_key.write(reinterpret_cast<const char *>(secret_key.data()), secret_key.size());
        out_pub_key.close();
        out_sec_key.close();
        return 0;
    }

    int key_mgr_init(std::string& pub_key_file_path, std::string& sec_key_file_path) {
        if(!is_empty) 
            return 0; // If already init.
        auto ret = load_local_key_files(pub_key_file_path, sec_key_file_path);
        if(ret != 0) {
            if(gen_key_save_to_local(pub_key_file_path, sec_key_file_path) != 0)
                return 1;
        }
        return 0;
    }
    const std::array<uint8_t, crypto_box_SECRETKEYBYTES>& get_secret_key() const {
        return secret_key;
    }
    const std::array<uint8_t, crypto_box_SECRETKEYBYTES>& get_public_key() const {
        return public_key;
    }
    bool is_activated() const {
        return !is_empty;
    }
};

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
        crypto_box_beforenm(aes256gcm_key.data(), client_public_key.data(), key_mgr.get_secret_key().data());
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

struct session_pool_stats {
    size_t total = 0;
    size_t empty = 0;
    size_t recycled = 0;
    size_t prepared = 0;
    size_t active = 0;
};

class session_pool {
    std::unordered_map<uint64_t, session_item> sessions;
    session_pool_stats stats;

    uint64_t gen_64bit_key() {
        std::array<uint8_t, 8> hash_key;
        randombytes_buf(hash_key.data(), hash_key.size());
        uint64_t ret = 0;
        for(uint8_t i = 0; i < 8; ++ i)
            ret |= (static_cast<uint64_t>(hash_key[i]) << (i * 8));
        return ret;
    }

public:
    session_pool() : stats({0, 0, 0, 0, 0}) {};

    int prepare_add_session(std::array<uint8_t, CID_BYTES>& recv_client_cid, std::array<uint8_t, crypto_box_PUBLICKEYBYTES>& recv_client_public_key, const curve25519_key_mgr& key_mgr) {
        if(!key_mgr.is_activated())
            return -1;
        uint64_t key = session_item::hash_client_info(recv_client_cid, recv_client_public_key);
        if(sessions.find(key) != sessions.end())
            return 1;
        session_item session(key);
        session.prepare(recv_client_cid, recv_client_public_key, key_mgr, true);
        sessions.insert({key, session});
        ++ stats.total;
        ++ stats.prepared;
        return 0;
    }
    session_item* get_session(uint64_t key) {
        auto it = sessions.find(key);
        if(it != sessions.end())
            return &(*it).second;
        return nullptr;
    }
    const bool is_session_stored(uint64_t key) {
        return (get_session(key) != nullptr);
    }
    bool delete_session(uint64_t key) {
        auto ptr = get_session(key);
        if(ptr == nullptr)
            return false;
        auto status = ptr->get_status();
        sessions.erase(key);
        -- stats.total;
        if(status == 0 || status == 1)
            -- stats.empty;
        else if(status == 2)
            -- stats.prepared;
        else if(status == 3)
            -- stats.active;
        else
            -- stats.recycled;
        return true;
    }
    int activate_session(uint64_t key) {
        auto ptr = get_session(key);
        if(ptr == nullptr)
            return -1;
        if(ptr->activate()) {
            ++ stats.active;
            -- stats.prepared;
            return 0;
        }
        return 1;
    }
};

// Connection Context contains an addr, a bind/empty uid, and a status
class ctx_item {
    std::string ctx_uid;        // Binded/Empty user unique ID
    int ctx_status;             // Status
                                // 0 - empty, wait for option (signup, signin, signout)
                                // 1 - signup or signin, auth info received (userid, password)
                                //     public_msg + encrypted_msg(0 - signup, 1 - signin, 2 - signout)
                                // 2 - signup or singin OK, good for messaging

public:
    ctx_item() : ctx_status(0) {
        ctx_uid.clear();
    }
    const std::string& get_bind_uid() const {
        return ctx_uid;
    }
    const int get_status() const {
        return ctx_status;
    }
    void set_bind_uid(const std::string& uid) {
        ctx_uid = uid;
    }
    void set_status(int status) {
        ctx_status = status;
    }
    void reset_ctx() { // Go back to status 1
        ctx_uid.clear();
        ctx_status = 1;
    }
    void clear_ctx() { // Clear everything
        ctx_uid.clear();
        ctx_status = 0;
    }
};

class ctx_pool {
    std::unordered_map<uint64_t, ctx_item> contexts;

public:
    ctx_pool() {};
    ctx_item *get_ctx(const uint64_t& key) {
        auto it = contexts.find(key);
        if(it == contexts.end())
            return nullptr;
        return &(*it).second;
    }
    std::unordered_map<uint64_t, ctx_item>& get_ctx_map() {
        return contexts;
    }
    bool add_ctx(uint64_t& key) {
        if(contexts.find(key) != contexts.end())
            return false;
        contexts.emplace(key, ctx_item());
        return true;
    }
    bool delete_ctx(uint64_t& key) {
        if(contexts.find(key) == contexts.end())
            return false;
        contexts.erase(key);
        return true;
    }
    bool is_valid_ctx(uint64_t& key) {
        return (contexts.find(key) != contexts.end());
    }
};

// Each user entry include a unique id and a hashed password
// This approach is not secure enough because we just used ordinary 
// SHA-256 to hash the password. Please use more secure one for serious
// purposes.
struct user_item {
    std::string unique_email;   // Original unique email address provided by user, the main key
    std::string unique_id;      // hex_str(sha256(unique_email))

    std::string unique_name;    // User self specified id. e.g.
    std::array<char, crypto_pwhash_STRBYTES> pass_hash;      // Hashed password

    uint8_t user_status;        // Currently, 0 - not in, 1 - signed in.
};


// The user storage is in memory, no persistence. Just for demonstration.
// Please consider using a database if you'd like to go further.
class user_mgr {
    // key: unique_email
    // value: user_item
    std::unordered_map<std::string, struct user_item> user_db;

    // key: unique_id
    // value: unique_email
    std::unordered_map<std::string, std::string> uname_uemail;
    std::string user_list_fmt;

public:
    user_mgr() {}

    // Only Alphabet, numbers, and special chars are allowed.
    // Length: 8-64
    static int pass_fmt_check(const std::string& pass_str) {
        if(pass_str.size() < PASSWORD_MIN_BYTES || pass_str.size() > PASSWORD_MAX_BYTES)
            return -1; // Length error.
        uint8_t contain_num = 0;
        uint8_t contain_lower_char = 0;
        uint8_t contain_special_char = 0;
        uint8_t contain_upper_char = 0;
        for(auto c : pass_str) {
            if(std::isdigit(static_cast<unsigned char>(c))) {
                contain_num = 1;
                continue;
            }
            if(std::islower(static_cast<unsigned char>(c))) {
                contain_lower_char = 1;
                continue;
            }
            if(std::isupper(static_cast<unsigned char>(c))) {
                contain_upper_char = 1;
                continue;
            }
            if(std::find(special_chars.begin(), special_chars.end(), c) != special_chars.end()) {
                contain_special_char = 1;
                continue;
            }
            return 1; // Illegal char found.
        }
        if(contain_num + contain_special_char + contain_lower_char + contain_upper_char < 3)
            return 2; // Not complex enough.
        return 0; // Good to go.
    }

    static std::array<char, crypto_pwhash_STRBYTES> get_pass_hash(std::string& password) {
        std::array<char, crypto_pwhash_STRBYTES> hashed_pwd;
        crypto_pwhash_str(
            hashed_pwd.data(), 
            password.c_str(), 
            password.size(), 
            crypto_pwhash_OPSLIMIT_INTERACTIVE, 
            crypto_pwhash_MEMLIMIT_INTERACTIVE
        );
        password.clear(); // For security reasons, we clean the string after hashing. 
        return hashed_pwd;
    }

    static int email_fmt_check(const std::string& email) {
        if(email.empty() || email.size() > UEMAIL_MAX_BYTES)
            return -1;
        std::regex email_regex(R"((?i)[a-z0-9._%+-]+@(?:[a-z0-9-]+\.)+[a-z]{2,})");
        if(!std::regex_match(email, email_regex)) 
            return 1;
        return 0;
    }

    bool is_email_registered(const std::string& email) {
        return (user_db.find(email) != user_db.end());
    }

    static std::string email_to_uid(const std::string& valid_email) {
        uint8_t sha256_hash[crypto_hash_sha256_BYTES];
        crypto_hash_sha256(sha256_hash, reinterpret_cast<const unsigned char*>(valid_email.c_str()), valid_email.size());
        char b64_cstr[crypto_hash_sha256_BYTES * 2];
        sodium_bin2base64(b64_cstr, crypto_hash_sha256_BYTES * 2, sha256_hash, crypto_hash_sha256_BYTES, sodium_base64_VARIANT_ORIGINAL);
        return std::string(b64_cstr);
    }

    // Only Alphabet, numbers, and hyphen are allowed.
    // Length: 4-64
    static int user_name_fmt_check(const std::string& uname) {
        if(uname.size() < ULOGIN_MIN_BYTES || uname.size() > UNAME_MAX_BYTES)
            return -1; // Length error.
        for(auto c : uname) {
            if(!std::isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_')
                return 1; // Illegal char found.
        }
        return 0; // Good to go.
    }

    // If the provided username is duplicated, try randomize it with a suffix
    // The suffix comes from a random 6-byte block (2 ^ 48 possibilities)
    // If the username is still duplicate after randomization, return false
    // else return true.
    bool randomize_username(std::string& duplicate_username) {
        uint8_t random_suffix[6];
        char b64_cstr[12]; // 2x is large enough for base64encode.
        // The b64_size includes a '\0' termination char.
        size_t b64_size = sodium_base64_encoded_len(6, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
        randombytes_buf(random_suffix, 6);
        sodium_bin2base64(b64_cstr, b64_size, 
            random_suffix, 6, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
        std::string new_username;
        if((duplicate_username.size() + 1 + b64_size) > UNAME_MAX_BYTES) {
            auto pos = UNAME_MAX_BYTES - b64_size - 1;
            new_username = duplicate_username.substr(0, pos) + "-" + std::string(b64_cstr);
        }
        else {
            new_username = duplicate_username + "-" + std::string(b64_cstr);
        }
        if(is_username_occupied(new_username))
            return false;
        duplicate_username = new_username;
        return true;
    }

    bool is_username_occupied(const std::string& uname) {
        return (uname_uemail.find(uname) != uname_uemail.end());
    }

    // Have to use pointer to avoid exception handling.
    const std::string* get_uemail_by_uname(const std::string& uname) {
        auto it = uname_uemail.find(uname);
        if(it == uname_uemail.end())
            return nullptr;
        return &(it->second);
    }

    user_item* get_user_item_by_uemail(const std::string& uemail) {
        auto it = user_db.find(uemail);
        if(it == user_db.end())
            return nullptr;
        return &(it->second);
    }

    user_item* get_user_item_by_uname(const std::string& uname) {
        auto uemail_ptr = get_uemail_by_uname(uname);
        if(uemail_ptr == nullptr)
            return nullptr;
        return get_user_item_by_uemail(*uemail_ptr);
    }

    auto get_total_user_num() {
        return user_db.size();
    }

    bool add_user(const std::string& uemail, std::string& uname, std::string& user_password, uint8_t& err) {
        err = 0;
        if(email_fmt_check(uemail) != 0) {
            err = 1;
            return false;
        }
        if(is_email_registered(uemail)) {
            err = 3;
            return false;
        }
        if(user_name_fmt_check(uname) != 0) {
            err = 5;
            return false;
        }
        if(pass_fmt_check(user_password) != 0) {
            err = 7;
            return false;
        }
        if(is_username_occupied(uname)) {
            if(!randomize_username(uname)) {
                err = 9;
                return false;
            }
        }
        struct user_item new_user;
        new_user.unique_email = uemail;
        new_user.unique_id = email_to_uid(uemail);
        new_user.unique_name = uname;
        new_user.pass_hash = get_pass_hash(user_password);
        user_db.insert({uemail, new_user});
        uname_uemail.insert({uname, uemail});
        user_list_fmt += (uname + " (" + uemail + ") " + "\n");
        return true;
    }

    // type = 0: uemail + password
    // type = 1 (or others): uname + password
    bool user_pass_check(const int type, const std::string& str, std::string& password) {
        user_item *ptr_item = nullptr;
        if(type == 0) {
            if(!is_email_registered(str)) {
                password.clear();
                return false;
            }
            ptr_item = get_user_item_by_uemail(str);
        }
        else {
            if(!is_username_occupied(str)) {
                password.clear();
                return false;
            }
            ptr_item = get_user_item_by_uname(str);
        }
        if(ptr_item == nullptr) {
            password.clear();
            return false;
        }
        auto ret = (crypto_pwhash_str_verify(
            (ptr_item->pass_hash).data(), 
            password.c_str(), 
            password.size()) == 0);

        password.clear();
        return ret;
    }

    std::string& get_user_list() {
        return user_list_fmt;
    }

    std::string get_user_list(bool show_status) {
        if(!show_status)
            return get_user_list();
        std::string list_with_status;
        for(auto& it : user_db) {
            if(it.second.user_status == 1)
                list_with_status += (it.second.unique_name + " (" + it.second.unique_email +  ") (in)\n");
            else
                list_with_status += ((it.second.unique_name) + " (" + it.second.unique_email + ")\n");
        }
        return list_with_status;
    }

    // type = 0: uemail + password
    // type = 1 (or others): uname + password
    bool set_user_status(const int type, const std::string& str, const uint8_t status) {
        user_item *ptr_item = nullptr;
        if(type == 0) 
            ptr_item = get_user_item_by_uemail(str);
        else
            ptr_item = get_user_item_by_uname(str);
        if(ptr_item == nullptr)
            return false;
        ptr_item->user_status = status;
        return true;
    }

    std::pair<size_t, size_t> get_user_stat() {
        size_t in = 0;
        for(auto& it : user_db) {
            if(it.second.user_status == 1)
                ++ in;
        }
        return std::make_pair(get_total_user_num(), in);
    }
};

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
    bool recv_size_too_small() const {
        return (recv_raw_bytes < 1 + CID_BYTES + crypto_box_PUBLICKEYBYTES);
    }
    bool recv_size_too_large() const {
        return (recv_raw_bytes == recv_raw_buffer.size());
    }
};

// The main class.
class udp_chatroom {
    struct sockaddr_in server_addr; // socket addr
    uint16_t port;                  // port number
    int server_fd;                  // generated server_fd
    curve25519_key_mgr key_mgr;     // key manager
    msg_buffer buffer;              // Message core processor
    user_mgr users;                // all users
    session_pool conns;             // all sessions.
    ctx_pool clients;               // all clients(contexts).
    int last_error;                 // error code
    
public:
    // A simple constructor
    udp_chatroom() {
        port = DEFAULT_PORT;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);
        server_fd = -1;
        key_mgr = curve25519_key_mgr();
        buffer = msg_buffer();
        users = user_mgr();
        conns = session_pool();
        clients = ctx_pool();
        last_error = 0;
    }

    // Close server and possible FD
    bool close_server(int err) {
        last_error = err;
        if(server_fd != -1) {
            close(server_fd); 
            server_fd = -1;
        }
        return err == 0;
    }

    // Get last error code
    int get_last_error(void) {
        return last_error;
    }

    // Start the server and handle possible failures
    bool start_server(void) {
        server_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if(server_fd == -1)
            return close_server(1);
        if(bind(server_fd, (sockaddr *)&server_addr, (socklen_t)sizeof(server_addr)))
            return close_server(3);
        std::cout << "UDP Chatroom Service started." << std::endl 
                  << "UDP Listening Port: " << port << std::endl;
        return true;
    }

    bool is_session_valid(const uint64_t& cinfo_hash) {
        return (conns.get_session(cinfo_hash) != nullptr);
    }

    // Simplify the socket send function.
    int simple_send(const uint64_t& cinfo_hash, const void *msg, size_t n) {
        auto p_conn = conns.get_session(cinfo_hash);
        if(p_conn == nullptr)
            return -3; // Invalid cinfo_hash
        auto addr = p_conn->get_src_addr();
        return sendto(server_fd, msg, n, MSG_CONFIRM, (struct sockaddr *)&addr, sizeof(addr));
    }

    // Simplify the socket send function.
    int simple_send(const struct sockaddr_in& addr, const void *msg, size_t n) {
        return sendto(server_fd, msg, n, MSG_CONFIRM, (struct sockaddr *)&addr, sizeof(addr));
    }

    // Simplify the socket send function.
    int simple_send(uint8_t header, const struct sockaddr_in& addr, const void *msg, size_t n) {
        if(n + 1 > buffer.send_buffer.size()) {
            return -3;
        }
        buffer.send_buffer[0] = header;
        std::copy(msg, msg + n, buffer.send_buffer.begin() + 1);
        buffer.send_bytes = n + 1;
        return sendto(server_fd, buffer.send_buffer.data(), buffer.send_bytes, MSG_CONFIRM, (struct sockaddr *)&addr, sizeof(addr));
    }

    // Simplify the socket send function.
    // Format : 1-byte header + public message + aes_nonce + aes_gcm_encrypted (sid + cinfo_hash + msg_body)
    int simple_secure_send(const uint8_t header, const std::array<uint8_t, crypto_aead_aes256gcm_KEYBYTES>& aes_key, const struct sockaddr_in& addr, const std::array<uint8_t, SID_BYTES>& sid, std::array<uint8_t, CIF_BYTES>& cif, const uint8_t *pub_msg, size_t pub_msg_n, const void *raw_msg, size_t raw_n) {
        std::array<uint8_t, crypto_aead_aes256gcm_NPUBBYTES> server_aes_nonce;
        size_t offset = 0, aes_encrypted_len = 0;

        // Padding the first byte
        buffer.send_buffer[0] = header;
        ++ offset;

        // pub_msg_n = 0 would be ordinary message.
        if(pub_msg_n <= SERVER_MSG_PUBBYTES_MAX && pub_msg_n > 0) {
            // Padding the public message part
            std::copy(pub_msg, pub_msg + pub_msg_n, buffer.send_buffer.begin() + offset);
            offset += pub_msg_n;
        }
    
        // Padding the aes_nonce
        session_item::generate_aes_nonce(server_aes_nonce);
        std::copy(server_aes_nonce.begin(), server_aes_nonce.end(), buffer.send_buffer.begin() + offset);
        offset += server_aes_nonce.size();

        // Construct the raw message: sid + cif + msg_body
        std::copy(sid.begin(), sid.end(), buffer.send_aes_buffer.begin());
        std::copy(cif.begin(), cif.end(), buffer.send_aes_buffer.begin() + sid.size());
        std::copy(raw_msg, raw_msg + raw_n, buffer.send_aes_buffer.begin() + sid.size() + cif.size());
        // Record the buffer occupied size.
        buffer.send_aes_bytes = sid.size() + cif.size() + raw_n;
        
        // AES encrypt and padding to the send_buffer.
        auto res = crypto_aead_aes256gcm_encrypt(
            buffer.send_buffer.data() + offset, 
            (unsigned long long *)&aes_encrypted_len,
            (const uint8_t *)buffer.send_aes_buffer.data(),
            buffer.send_aes_bytes, 
            NULL, 0, NULL, 
            server_aes_nonce.data(), aes_key.data()
        );
        buffer.send_bytes = offset + aes_encrypted_len;

        if(res != 0) 
            return -1;
        auto ret = simple_send(addr, buffer.send_buffer.data(), buffer.send_bytes);
        if(ret < 0) 
            return -3;
        return ret;
    }

    int notify_reset_conn(uint64_t& cinfo_hash, const void *msg, size_t size_of_msg, bool clean_client) {
        auto ret1 = simple_send(cinfo_hash, msg, size_of_msg);
        auto ret2 = simple_send(cinfo_hash, connection_reset, sizeof(connection_reset));
        int ret3 = 1;
        if(clean_client) {
            clients.get_ctx(cinfo_hash)->clear_ctx();
        } 
        else {
            ret3 = simple_send(cinfo_hash, main_menu, sizeof(main_menu));
            clients.get_ctx(cinfo_hash)->reset_ctx();
        }
        if((ret1 >= 0) && (ret2 >= 0) && (ret3 >= 0))
            return 0;
        return 1;
    }

    // Convert an addr to a message
    static std::string addr_to_msg(const struct sockaddr_in addr) {
        std::ostringstream oss;
        char ip_cstr[INET_ADDRSTRLEN];
        std::strncpy(ip_cstr, inet_ntoa(addr.sin_addr), INET_ADDRSTRLEN);
        oss << ip_cstr << ":" << ntohs(addr.sin_port) << std::endl;
        return oss.str();
    }

    static std::string get_current_time(void) {
        auto now = std::chrono::system_clock::now();
        std::time_t now_t = std::chrono::system_clock::to_time_t(now);
        std::tm* now_tm = std::gmtime(&now_t);
        std::ostringstream oss;
        oss << (now_tm->tm_year + 1900) << '-' 
            << (now_tm->tm_mon + 1) << '-'
            << (now_tm->tm_mday) << '-'
            << (now_tm->tm_hour) << ':' << (now_tm->tm_min) << ':' << (now_tm->tm_sec);
        return oss.str();
    }

    bool get_cinfo_by_uid(uint64_t& ret, const std::string& user_uid) {
        auto map = clients.get_ctx_map();
        for(auto it : map) {
            if(it.second.get_bind_uid() == user_uid) {
                ret = it.first; 
                return true;
            }
        }
        return false;
    }

    bool is_user_signed_in(const std::string& user_uid) {
        auto map = clients.get_ctx_map();
        uint64_t tmp;
        return get_cinfo_by_uid(tmp, user_uid);
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

    // Broadcasting to all connected clients (include or exclude current/self).
    size_t system_secure_broadcasting(bool include_self, std::string unique_name, uint8_t header, const void *raw_msg, size_t raw_n) {
        std::string msg = "[SYSTEM_BROADCAST]: [UID]";
        msg += unique_name;
        std::string msg_str(static_cast<const char *>(raw_msg), raw_n);
        msg += msg_str;
        size_t sent_out = 0;
        for(auto elem : clients.get_ctx_map()) {
            if(elem.second.get_status() != 6)
                continue;
            if(elem.second.get_bind_uid() == unique_name && !include_self)
                continue;
            auto cif = elem.first;
            session_item *ptr_session = conns.get_session(cif);
            if(ptr_session == nullptr)
                continue;
            auto aes_key = ptr_session->get_aes_gcm_key();
            auto addr = ptr_session->get_src_addr();
            auto sid = ptr_session->get_server_sid();
            auto cif_bytes = u64_to_bytes(cif);

            if(simple_secure_send(header, aes_key,  addr, sid, cif_bytes, nullptr, 0, raw_msg, raw_n) >= 0)
                ++ sent_out;
        }
        return sent_out;
    }

    /* int msg_precheck(const conn_ctx& this_ctx, const std::string& buff_str, struct msg_attr& attr) {
        attr.msg_attr_reset(); // Reset all the attrbutes.
        auto is_private_msg = (std::memcmp(buff_str.c_str(), to_user, MSG_ATTR_LEN) == 0);
        auto is_tagged_msg = (std::memcmp(buff_str.c_str(), tag_user, MSG_ATTR_LEN) == 0);
        if(is_private_msg || is_tagged_msg) {
            const size_t start_pos = sizeof(to_user);
            size_t delim_pos = buff_str.find(user_delim, start_pos);
            std::string target_user;
            if(delim_pos == std::string::npos) 
                target_user = buff_str.substr(start_pos); 
            else
                target_user = buff_str.substr(start_pos, delim_pos - start_pos);
            if(target_user == this_ctx.get_bind_uid())
                return -1; // User cannot tag or send private messages to self
                           // Will not set the attrbutes.
            if(all_users.is_in_db(target_user)) { // If the target uid is valid
                if(!is_user_signed_in(target_user))
                    return 1;   // tagged or private message requires target user signed in.
                                // false will bounce the msg back to sender.
                                // will not set the attributes.
                attr.target_uid = target_user;
                attr.target_ctx_idx = get_client_idx(target_user);
                attr.is_set = true; // Attributes set.
                if(!is_private_msg) 
                    attr.msg_attr_mask = 1; // Public but tagged
                else
                    attr.msg_attr_mask = 2; // Private
                return 0; // msg_attr_mask set and return true
            }
            attr.is_set = true; // Attributes set.
            // If the target user uid is invalid, do nothing
            return 0;
        }
        attr.is_set = true; // Attributes set.
        // If normal message, do nothing.
        return 0;
    } */

    /* Assemble the message header for a connection context
    std::string assemble_msg_header(const uint64_t& cinfo_hash) {
        auto ctx_ptr = clnts.get_ctx_by_key(cinfo_hash);
        if(ctx_ptr == nullptr) 
            return "";
        std::string curr_time = get_current_time();
        std::ostringstream oss;
        oss << std::endl << curr_time << " [FROM_UID] " 
            << ctx_ptr->get_bind_uid() << ":" << std::endl << "----  ";
        return oss.str(); 
    }*/

    /* Must call msg_precheck first!!!
    bool update_msg_buffer(std::vector<char>& buffer, const struct msg_attr& attr, const conn_ctx& ctx) {
        if(!attr.is_set)
            return false;
        std::string msg_header = assemble_msg_header(ctx);
        if(attr.msg_attr_mask != 0)
            buffer.erase(buffer.begin(), buffer.begin() + MSG_ATTR_LEN + attr.target_uid.size() + 1);
        if(attr.msg_attr_mask == 1) 
            msg_header += (std::string("@tagged@") + attr.target_uid + std::string(" "));
        else if(attr.msg_attr_mask == 2)
            msg_header += (std::string("*privto*") + attr.target_uid + std::string(" "));
        buffer.insert(buffer.begin(), msg_header.c_str(), msg_header.c_str() + msg_header.size());
        buffer.back() = '\n';
        buffer.push_back('\n');
        buffer.push_back('\0');
        return true;
    }*/

    std::string user_list_to_msg() {
        std::string user_list_fmt = users.get_user_list(true);
        std::ostringstream oss;
        std::pair<size_t, size_t> stat_par = users.get_user_stat();
        oss << "[SYSTEM_INFO] currently " << stat_par.first << " signed up users, " 
            << stat_par.second << " signed in users. list:\n"
            << "* (in) currently signed in.\n" << user_list_fmt << "\n\n"; 
        return oss.str();
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

    bool is_valid_clnt_err_msg(const uint8_t *clnt_err_code, uint64_t& cinfo_hash) {
        if(buffer.recv_raw_bytes != 1 + ERR_CODE_BYTES + CID_BYTES + crypto_box_PUBLICKEYBYTES)
            return false;
        auto err_start = buffer.recv_raw_buffer.data() + 1;
        if(std::memcmp(err_start, clnt_err_code, ERR_CODE_BYTES) != 0)
            return false; // Garbage message, ommit.
        auto pos = buffer.recv_raw_buffer.begin() + 1 + ERR_CODE_BYTES;
        std::array<uint8_t, CID_BYTES> cid;
        std::array<uint8_t, crypto_box_PUBLICKEYBYTES> cpk;
        std::copy(pos, pos + CID_BYTES, cid.begin());
        std::copy(pos + CID_BYTES, pos + CID_BYTES + crypto_box_PUBLICKEYBYTES, cpk.begin());
        uint64_t hash = session_item::hash_client_info(cid, cpk);
        if(is_session_valid(hash)) {
            cinfo_hash = hash;
            return true;
        }
        return false;
    }

    // Main processing method.
    int run_server(void) {
        if(server_fd == -1) {
            std::cout << "Server not started." << std::endl;
            return -1;
        }
        if(!key_mgr.is_activated()) {
            std::cout << "Key manager not activated." << std::endl;
            return -3;
        }
        auto server_public_key = key_mgr.get_public_key();
        ctx_user_bind_buffer bind_buffer;
        //std::array<uint8_t, crypto_aead_aes256gcm_NPUBBYTES> server_aes_nonce;
        std::array<uint8_t, crypto_aead_aes256gcm_NPUBBYTES> client_aes_nonce;
        size_t aes_encrypted_len = 0;
        size_t aes_decrypted_len = 0;
        while(true) {
            struct sockaddr_in client_addr;
            auto addr_len = sizeof(client_addr);
            buffer.clear_buffer();
            auto bytes_recv = recvfrom(server_fd, buffer.recv_raw_buffer.data(), buffer.recv_raw_buffer.size(), MSG_WAITALL, (struct sockaddr *)&client_addr, (socklen_t *)&addr_len);
            buffer.recv_raw_bytes = bytes_recv;
            if(buffer.recv_size_too_small() || buffer.recv_size_too_large())
                continue; // If size is invalid, ommit.
            std::cout << ">> Received from: " << std::endl << inet_ntoa(client_addr.sin_addr) \
                      << ':' << ntohs(client_addr.sin_port) << '\t' << buffer.recv_raw_buffer.data() << std::endl;
            auto header = buffer.recv_raw_buffer[0];
            if(header == 0x00 || header == 0x01) {
                if(buffer.recv_raw_bytes != 1 + CID_BYTES + crypto_box_PUBLICKEYBYTES) {
                    simple_send(client_addr, server_ff_failed, sizeof(server_ff_failed));
                    continue;
                }
                auto pos = buffer.recv_raw_buffer.begin() + 1;
                std::array<uint8_t, CID_BYTES> cid;
                std::array<uint8_t, crypto_box_PUBLICKEYBYTES> cpk;
                std::copy(pos, pos + CID_BYTES, cid.begin());
                std::copy(pos + CID_BYTES,pos + CID_BYTES + crypto_box_PUBLICKEYBYTES, cpk.begin());
                uint64_t cinfo_hash = session_item::hash_client_info(cid, cpk);
                if(conns.get_session(cinfo_hash) != nullptr)
                    continue; // If the session has been established, ommit.
                conns.prepare_add_session(cid, cpk, key_mgr);
                auto this_conn = conns.get_session(cinfo_hash);
                if(this_conn == nullptr) {
                    simple_send(client_addr, (const uint8_t *)server_internal_fatal, sizeof(server_internal_fatal));
                    return -5;
                }
                this_conn->set_src_addr(client_addr);
                auto aes_key = this_conn->get_aes_gcm_key();
                auto sid = this_conn->get_server_sid();
                auto cinfo_hash_bytes = u64_to_bytes(cinfo_hash);
                if(header == 0x00)
                    simple_secure_send(0x00, aes_key, client_addr, sid, cinfo_hash_bytes, server_public_key.data(), server_public_key.size(), ok, sizeof(ok));
                else
                    simple_secure_send(0x01, aes_key, client_addr, sid, cinfo_hash_bytes, nullptr, 0, ok, sizeof(ok));
                continue;
            }
            if(header == 0xFF || header == 0xEF || header == 0xDF) {
                uint64_t cinfo_hash;
                if(header == 0xFF) {
                    if(!is_valid_clnt_err_msg(client_ff_timout, cinfo_hash))
                    continue;
                }
                else if(header == 0xEF) {
                    if(!is_valid_clnt_err_msg(client_ef_keyerr, cinfo_hash))
                    continue;
                }
                else {
                    if(!is_valid_clnt_err_msg(client_df_msgerr, cinfo_hash))
                    continue;
                }
                if(conns.get_session(cinfo_hash)->get_status() != 1)
                    continue;
                simple_send(client_addr, (const uint8_t *)restart_handshake, sizeof(restart_handshake));
                conns.delete_session(cinfo_hash);
                continue;
            }
            if(header == 0x02) {
                if(buffer.recv_raw_bytes != 1 + CIF_BYTES + crypto_aead_aes256gcm_NPUBBYTES + SID_BYTES + sizeof(ok) + crypto_aead_aes256gcm_ABYTES)
                    continue;
                auto pos = buffer.recv_raw_buffer.begin() + 1;
                std::array<uint8_t, CIF_BYTES> cinfo_hash_bytes;
                std::copy(pos, pos + CIF_BYTES, cinfo_hash_bytes.begin());
                std::copy(pos + CIF_BYTES, pos + CIF_BYTES + crypto_aead_aes256gcm_NPUBBYTES, client_aes_nonce.begin());
                
                auto cinfo_hash = bytes_to_u64(cinfo_hash_bytes);
                auto this_conn = conns.get_session(cinfo_hash);
                if(this_conn == nullptr)
                    continue; // If this is not a established session, omit.
                if(this_conn->get_status() != 1)
                    continue; // If it is not a prepared session, omit.
                auto aes_key = this_conn->get_aes_gcm_key();
                auto server_sid = this_conn->get_server_sid();
                aes_decrypted_len = 0;

                auto is_aes_ok = 
                    ((crypto_aead_aes256gcm_decrypt(
                        buffer.recv_aes_buffer.begin(), (unsigned long long *)aes_decrypted_len,
                        NULL,
                        pos + CIF_BYTES + crypto_aead_aes256gcm_NPUBBYTES, SID_BYTES + sizeof(ok) + crypto_aead_aes256gcm_ABYTES,
                        NULL, 0,
                        client_aes_nonce.data(), aes_key.data()
                    ) == 0) && (aes_decrypted_len == SID_BYTES + sizeof(ok)));

                buffer.recv_aes_bytes = aes_decrypted_len;

                auto is_msg_ok = 
                    ((std::memcmp(buffer.recv_aes_buffer.data(), server_sid.data(), SID_BYTES) == 0 &&
                    std::memcmp(buffer.recv_aes_buffer.data() + SID_BYTES, ok, sizeof(ok)) == 0));
                
                if(is_aes_ok && is_msg_ok) {
                    this_conn->activate(); // Activate the session
                    this_conn->set_src_addr(client_addr); // Update the addr.
                    simple_secure_send(0x02, aes_key, client_addr, server_sid, cinfo_hash_bytes, nullptr, 0, ok, sizeof(ok));
                    continue;
                }
                if(!is_aes_ok) 
                    std::copy(std::begin(server_ef_keyerr), std::end(server_ef_keyerr), buffer.send_buffer.begin());
                else
                    std::copy(std::begin(server_df_msgerr), std::end(server_df_msgerr), buffer.send_buffer.begin());
                std::copy(server_public_key.begin(), server_public_key.end(), buffer.send_buffer.begin() + ERR_CODE_BYTES + 1);
                buffer.send_bytes = ERR_CODE_BYTES + 1 + server_public_key.size();
                simple_send(client_addr, buffer.send_buffer.data(), buffer.send_bytes);
                simple_send(client_addr, (const uint8_t *)restart_handshake, sizeof(restart_handshake));
                conns.delete_session(cinfo_hash);
                continue;
            }
            if(header == 0x10) {
                if(buffer.recv_raw_bytes <= 1 + CIF_BYTES + crypto_aead_aes256gcm_NPUBBYTES + SID_BYTES + crypto_aead_aes256gcm_ABYTES)
                    continue; // Empty or invalid message. Omit.

                // Try to handle that.
                auto pos = buffer.recv_raw_buffer.begin() + 1;
                std::array<uint8_t, CIF_BYTES> cinfo_hash_bytes;

                std::copy(pos, pos + CIF_BYTES, cinfo_hash_bytes.begin());
                std::copy(pos + CIF_BYTES, pos + CIF_BYTES + crypto_aead_aes256gcm_NPUBBYTES, client_aes_nonce.begin());

                auto cinfo_hash = bytes_to_u64(cinfo_hash_bytes);
                auto this_conn = conns.get_session(cinfo_hash);
                if(this_conn == nullptr)
                    continue; // Not a valid session.
                if(this_conn->get_status() != 2)
                    continue; // Not an activated session
                auto aes_key = this_conn->get_aes_gcm_key();
                auto server_sid = this_conn->get_server_sid();
                aes_decrypted_len = 0;

                auto is_msg_ok = 
                    ((crypto_aead_aes256gcm_decrypt(
                        buffer.recv_aes_buffer.begin(), (unsigned long long *)aes_decrypted_len,
                        NULL,
                        pos + CIF_BYTES + crypto_aead_aes256gcm_NPUBBYTES, 
                        buffer.recv_raw_bytes - 1 - CIF_BYTES - crypto_aead_aes256gcm_NPUBBYTES,
                        NULL, 0,
                        client_aes_nonce.data(), aes_key.data()
                    ) == 0) && std::memcmp(buffer.recv_aes_buffer.data(), server_sid.data(), SID_BYTES) == 0);

                buffer.recv_aes_bytes = aes_decrypted_len;
                if(!is_msg_ok) {
                    std::copy(std::begin(server_cf_siderr), std::end(server_cf_siderr), buffer.send_buffer.begin());
                    buffer.send_bytes = ERR_CODE_BYTES + 1;
                    simple_send(client_addr, buffer.send_buffer.data(), buffer.send_bytes);
                    continue;
                }

                auto msg_body = buffer.recv_aes_buffer.data() + SID_BYTES;
                auto msg_size = aes_decrypted_len - SID_BYTES;

                this_conn->set_src_addr(client_addr); // Update the client addr.

                if(!clients.is_valid_ctx(cinfo_hash)) 
                    clients.add_ctx(cinfo_hash);

                auto this_client = clients.get_ctx(cinfo_hash);
                if(this_client == nullptr)
                    continue; // Abnormal. 

                auto stat = this_client->get_status();
                if(stat == 0) {
                    simple_send(0x10, client_addr, (const uint8_t *)main_menu, sizeof(main_menu));
                    this_client->set_status(1);
                    continue;
                }
                if(stat == 1) {
                    if(msg_size < 1 + 1 + ULOGIN_MIN_BYTES + 1 + PASSWORD_MIN_BYTES + 1)
                        continue; // option + type + user_name &/user_email + '0x00' + password + 0x00
                    if(msg_size > 1 + 1 + UEMAIL_MAX_BYTES + 1 + UNAME_MAX_BYTES + 1 + PASSWORD_MAX_BYTES + 1)
                        continue; // invalid format - the message is too long.

                    auto option = msg_body[0];
                    auto login_type = msg_body[1];

                    // option: 0 - signup, 1 - signin

                    if(option != '0' && option != '1') 
                        continue; // Invalid option

                    if(option == 0) { // Signing up.
                        if(msg_size < 1 + 1 + ULOGIN_MIN_BYTES + 1 + ULOGIN_MIN_BYTES + 1 + PASSWORD_MIN_BYTES + 1)
                            continue; // Invalid length.

                        auto reg_info = split_buffer_by_null(msg_body + 2, msg_size - 2, 3);
                        if(reg_info.size() < 3) 
                            continue; // Invalid format.

                        uint8_t err = 0;
                        if(!users.add_user(reg_info[0], reg_info[1], reg_info[2], err)) {
                            simple_secure_send(0x10, aes_key, client_addr, server_sid, cinfo_hash_bytes, nullptr, 0, &err, 1);
                            continue;
                        }
                        const char msg[] = " signed up and signed in!\n";
                        system_secure_broadcasting(false, reg_info[1], 0x10, msg, sizeof(msg));

                        this_client->set_bind_uid(reg_info[0]);
                        this_client->set_status(2);
                        users.set_user_status(0, reg_info[0], 1);
                        continue;
                    }

                    
                    

                    if(msg_size == 1 && msg_body[0] == '1') {
                        simple_send(0x11, client_addr, (const uint8_t *)input_username, sizeof(input_username));
                        this_client->set_status(2);
                    }
                    else if(msg_size == 1 && msg_body[0] == '2') {
                        simple_send(0x11, client_addr, (const uint8_t *)input_username, sizeof(input_username));
                        this_client->set_status(3);
                    }
                    else {
                        simple_send(0x11, client_addr, (const uint8_t *)option_error, sizeof(option_error));
                        this_client->reset_ctx();
                    }
                    continue;
                }
                if(stat == 2 || stat == 3) {
                    std::string msg_str(reinterpret_cast<const char *>(msg_body), msg_size);
                    auto check_flag = users.user_uid_check(msg_str);
                    if(check_flag == -1) {
                        simple_send(0x11, client_addr, (const uint8_t *)invalid_uid_len, sizeof(invalid_uid_len));
                        this_client->reset_ctx();
                        continue;
                    }
                    if(check_flag == 1) {
                        simple_send(0x11, client_addr, (const uint8_t *)invalid_uid_fmt, sizeof(invalid_uid_fmt));
                        this_client->reset_ctx();
                        continue;
                    }
                    if(stat == 2) {
                        if(users.is_in_db(msg_str)) {
                            simple_send(0x11, client_addr, (const uint8_t *)user_uid_exist, sizeof(user_uid_exist));
                            this_client->reset_ctx();
                            continue;
                        }
                        simple_send(0x11, client_addr, (const uint8_t *)input_password, sizeof(input_password));
                        this_client->set_bind_uid(msg_str);
                        this_client->set_status(4);
                        continue;
                    }
                    if(!users.is_in_db(msg_str)) {
                        simple_send(0x11, client_addr, (const uint8_t *)user_uid_error, sizeof(user_uid_error));
                        this_client->reset_ctx();
                        continue;
                    }
                    uint64_t res;
                    if(get_cinfo_by_uid(res, msg_str)) {

                    }
                }
            }


            

            if(stat == 2 || stat == 3) {
                auto flag = all_users.user_uid_check(buff_str);
                if(flag == -1) {
                    notify_reset_conn(invalid_uid_len, sizeof(invalid_uid_len), client, false);
                    continue;
                }
                if(flag == 1) {
                    notify_reset_conn(invalid_uid_fmt, sizeof(invalid_uid_fmt), client, false);
                    continue;
                }
                if(stat == 2) {
                    if(all_users.is_in_db(buff_str)) {
                        notify_reset_conn(user_uid_exist, sizeof(user_uid_exist), client, false);
                        continue;
                    }
                    simple_send(input_password, sizeof(input_password), client_addr);
                    client.set_bind_uid(buff_str);
                    client.set_status(4);
                    continue;
                }
                
                if(!all_users.is_in_db(buff_str)) {
                    notify_reset_conn(user_uid_error, sizeof(user_uid_error), client, false);
                    continue;
                }
                auto client_idx = get_client_idx(buff_str);
                if(client_idx != clients.size()) {
                    simple_send(user_already_signin, sizeof(user_already_signin), client_addr);
                    std::string addr_msg = addr_to_msg(*(clients[client_idx].get_conn_addr()));
                    simple_send(addr_msg.c_str(), addr_msg.size(), client_addr);
                    simple_send(user_resign_in, sizeof(user_resign_in), client_addr);
                    bind_buffer.set_bind_buffer(buff_str, client_idx);
                    client.set_status(100);
                    continue;
                }
                simple_send(input_password, sizeof(input_password), client_addr);
                client.set_bind_uid(buff_str);
                client.set_status(5);
                continue;
            }
                
            if(stat == 4 || stat == 5) {
                std::string user_uid = client.get_bind_uid();
                auto flag = all_users.pass_str_check(buff_str);
                if(stat == 4) {
                    if(flag == -1) {
                        notify_reset_conn(invalid_pass_len, sizeof(invalid_pass_len), client, false);
                        continue;
                    }
                    if(flag != 0) {
                        notify_reset_conn(invalid_pass_fmt, sizeof(invalid_pass_fmt), client, false);
                        continue;
                    }
                    all_users.add_user(user_uid, buff_str);
                    all_users.set_user_status(user_uid, 1);
                    auto user_list_msg = user_list_to_msg();
                    simple_send(signup_ok, sizeof(signup_ok), client_addr);
                    simple_send(user_list_msg.c_str(), user_list_msg.size(), client_addr);
                    std::string msg_body = " signed up and in!\n\n";
                    system_broadcasting(false, user_uid, msg_body);
                    client.set_status(6);
                    continue;
                }
                if(flag != 0) {
                    notify_reset_conn(invalid_pass, sizeof(invalid_pass), client, false);
                    continue;
                }
                if(!all_users.is_user_pass_valid(user_uid, buff_str)) {
                    notify_reset_conn(password_error, sizeof(password_error), client, false);
                    continue;
                }
                all_users.set_user_status(user_uid, 1);
                auto user_list_msg = user_list_to_msg();
                simple_send(signin_ok, sizeof(signin_ok), client_addr);
                simple_send(user_list_msg.c_str(), user_list_msg.size(), client_addr);
                std::string msg_body = " signed in!\n\n";
                system_broadcasting(false, user_uid, msg_body);
                if(bind_buffer.is_set_buffer()) {
                    notify_reset_conn(client_switched, sizeof(client_switched), clients[bind_buffer.get_prev_ctx_idx()], true);
                    bind_buffer.unset_bind_buffer();
                }
                
                client.set_status(6);
                continue;
            }
            
            std::string user_uid = client.get_bind_uid();
            if(buff_str == "~:q!") {
                notify_reset_conn(signed_out, sizeof(signed_out), client, true);
                std::string msg_body = " signed out!\n\n";
                system_broadcasting(false, user_uid, msg_body);
                all_users.set_user_status(user_uid, 0);
                continue;
            }
            if(buff_str == "~:lu") {
                auto user_list_msg = user_list_to_msg();
                simple_send(user_list_msg.c_str(), user_list_msg.size(), client_addr);
                continue;
            }
            if(buff_str.empty()) {
                continue; // Empty messages will be skipped.
            }
            struct msg_attr attr;
            auto check = msg_precheck(client, buff_str, attr);
            if(check == 1) {
                simple_send(cannot_at_or_to_user, sizeof(cannot_at_or_to_user), client_addr);
                continue;
            }
            if(check == -1) {
                simple_send(cannot_at_or_to_self, sizeof(cannot_at_or_to_self), client_addr);
                continue;
            }
            if(!update_msg_buffer(buffer, attr, client)) {
                std::string internal_bug = "internal error, probably a bug. Please report to us.\n";
                system_broadcasting(true, "[ALL]", internal_bug);
                continue;
            }
            if(attr.msg_attr_mask == 0) {
                for(auto& item : clients) {
                    if(item.get_status() == 6)
                        simple_send(buffer.data(), buffer.size(), *(item.get_conn_addr()));
                }
                continue;
            }
            if(attr.msg_attr_mask == 1) {
                for(auto& item : clients) {
                    if(item.get_status() == 6) {
                        if(item.get_bind_uid() == attr.target_uid)
                            simple_send(been_tagged, sizeof(been_tagged), *(clients[attr.target_ctx_idx].get_conn_addr()));
                            simple_send(buffer.data(), buffer.size(), *(item.get_conn_addr()));
                    }
                }
                continue;
            }

            simple_send(private_msg_sent, sizeof(private_msg_sent), client_addr);
            simple_send(buffer.data(), buffer.size(), client_addr);
            simple_send(private_msg_recved, sizeof(private_msg_recved), *(clients[attr.target_ctx_idx].get_conn_addr()));
            simple_send(buffer.data(), buffer.size(), *(clients[attr.target_ctx_idx].get_conn_addr()));
        }
    }
};

// The simplest driver. You can improve it if you'd like to go further.
int main(int argc, char **argv) {
    udp_chatroom new_server;
    if(sodium_init() < 0) {
        std::cout << "Failed to init libsodium." << std::endl;
        return 1;
    }
    if(!new_server.start_server()) {
        std::cout << "Failed to start server. Error Code: " 
                  << new_server.get_last_error() << std::endl;
        return 3;
    }
    return new_server.run_server();
}
