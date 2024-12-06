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

constexpr uint8_t const_cid_bytes = 8;
constexpr uint8_t const_sid_bytes = 8;
constexpr size_t uid_maxlen = 64;
constexpr size_t uid_minlen = 4;
constexpr size_t password_maxlen = 32;
constexpr size_t password_minlen = 4;
constexpr uint16_t default_port = 8081;
constexpr size_t buff_size = 4096;
constexpr char special_chars[] = "~!@#$%^&(){}[]-_=+;:,.<>/|";

constexpr uint8_t server_ff_failed[] = {0xFF, 'F', 'A', 'I', 'L', 'E', 'D'};
constexpr uint8_t server_ef_keyerr[] = {0xEF, 'K', 'E', 'Y', 'E', 'R', 'R'};
constexpr uint8_t server_df_msgerr[] = {0xDF, 'M', 'S', 'G', 'E', 'R', 'R'};
constexpr uint8_t server_cf_siderr[] = {0xCF, 'S', 'I', 'D', 'E', 'R', 'R'};

constexpr char main_menu[] = "1. signup\n2. signin\nPlease choose (1 | 2): ";
constexpr char input_username[] = "Username: ";
constexpr char input_password[] = "Password: ";
constexpr char option_error[] = "option error, please input 1 or 2\n";
constexpr char user_uid_exist[] = "user already exists.\n";
constexpr char user_uid_error[] = "user does not exist.\n";
constexpr char password_error[] = "password doesn't match.\n";
constexpr char invalid_uid_fmt[] = "invalid uid format, rules to follow:\n\
    4-64 ascii chars.\n\
    a-z, A-Z, numbers, and/or hyphen-.\n";
constexpr char invalid_uid_len[] = "invalid uid length: 4-64\n";
constexpr char invalid_pass_fmt[] = "invalid password format, rules to follow:\n\
    4-32 ascii chars.\n\
    a-z, A-Z, numbers, and special chars, no spaces.\n\
    * must contains at least 3 out of 4 types above.\n";
constexpr char invalid_pass[] = "not a valid password string.\n";
constexpr char invalid_pass_len[] = "invalid password length: 4-32\n";
constexpr char signup_ok[] = "[SYSTEM_WELCOME] signed up and signed in.\n\
[SYSTEM_WELCOME] send ~:q! to sign out.\n\
[SYSTEM_WELCOME] send ~-@uid: to tag another user.\n\
[SYSTEM_WELCOME] send ~->uid: to send private messages to another user.\n\n";
constexpr char signin_ok[] = "[SYSTEM_WELCOME] signed in.\n\
[SYSTEM_WELCOME] send ~:q! to sign out.\n\
[SYSTEM_WELCOME] send ~-@uid: to tag another user.\n\
[SYSTEM_WELCOME] send ~->uid: to send private messages to another user.\n\n";
constexpr char password_not_complex[] = "the password is not complex enough.\n";
constexpr char signed_out[] = "[SYSTEM] you have signed out.\n";
constexpr char user_already_signin[] = "user already signed in at client: ";
constexpr char user_resign_in[] = "this signin would quit that client, are you sure? (yes | no)\n";
constexpr char another_sign_warn[] = "[SYSTEM_WARN] another client is trying to sign in your uid!\n";
constexpr char not_yes_or_no[] = "option error, please send either yes or no\n";
constexpr char option_denied[] = "you sent no. nothing changed.\n";
constexpr char client_switched[] = "you've resigned in on another client. signed out here.\n";
constexpr char connection_reset[] = "this connection has been reset.\n\n";
constexpr char cannot_at_or_to_user[] = "[SYSTEM] target user not signed in.\n";
constexpr char cannot_at_or_to_self[] = "[SYSTEM] you cannot tag or send privated messages to yourself.\n";
constexpr char been_tagged[] = "[SYSTEM_NOTIFY] you've been tagged!";
constexpr char private_msg_recved[] = "[SYSTEM_NOTIFY] you've received a private message!";
constexpr char private_msg_sent[] = "[SYSTEM_INFO] you've sent a private message!";
constexpr size_t MSG_ATTR_LEN = 3;
constexpr char to_user[MSG_ATTR_LEN] = {'~', '-', '>'};
constexpr char tag_user[MSG_ATTR_LEN] = {'~', '-', '@'};
constexpr char user_delim = ':';

// Each user entry include a unique id and a hashed password
// This approach is not secure enough because we just used ordinary 
// SHA-256 to hash the password. Please use more secure one for serious
// purposes.
struct user_entry {
    std::string user_uid;   // Unique ID
    std::string pass_hash;  // Hashed password
    uint8_t user_status;    // Currently, 0 - not in, 1 - signed in.
};

class ctx_user_bind_buffer {
    std::string user_uid;
    session_ctx *prev_ctx;
    bool is_set;
public:
    ctx_user_bind_buffer() : prev_ctx(nullptr), is_set(false) {
        user_uid.clear();
    }
    void set_bind_buffer(const std::string& uid, session_ctx *p_ctx) {
        user_uid = uid;
        prev_ctx = p_ctx;
        is_set = true;
    }
    void unset_bind_buffer(void) {
        user_uid.clear();
        prev_ctx = nullptr;
        is_set = false;
    }
    const bool is_set_buffer(void) const {
        return is_set;
    }
    const std::string& get_user_uid() {
        return user_uid;
    }
    const session_ctx* get_prev_ctx_idx() const {
        return prev_ctx;
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
    std::array<uint8_t, crypto_box_SECRETKEYBYTES> private_key;
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
        std::vector<uint8_t> public_key_vec, private_key_vec;
        auto ret = read_curve25519_key_file(pub_key_file, public_key_vec, crypto_box_PUBLICKEYBYTES);
        if(ret != 0)
            return ret; // 1, 3, 5
        ret = read_curve25519_key_file(priv_key_file, private_key_vec, crypto_box_SECRETKEYBYTES);
        if(ret != 0)
            return -ret; // -1, -3, -5
        uint8_t random_msg[32];
        uint8_t enc_msg[crypto_box_SEALBYTES + sizeof(random_msg)];
        uint8_t dec_msg[sizeof(random_msg)];
        randombytes_buf(random_msg, sizeof(random_msg));
        crypto_box_seal(enc_msg, random_msg, sizeof(random_msg), public_key_vec.data());
        if(crypto_box_seal_open(dec_msg, enc_msg, sizeof(enc_msg), public_key_vec.data(), private_key_vec.data()) != 0)
            return 7;
        if(std::memcmp(random_msg, dec_msg, sizeof(random_msg)) == 0) {
            std::copy(public_key_vec.begin(), public_key_vec.end(), public_key);
            std::copy(private_key_vec.begin(), private_key_vec.end(), private_key);
            is_empty = false;
            return 0;
        }
        return 7; // key doesn't match
    }

    // This is a force operation, no status check.
    int gen_key_save_to_local(std::string& pubkey_file_path, std::string& privkey_file_path) {
        std::ofstream out_pubkey(pubkey_file_path, std::ios::binary);
        if(!out_pubkey.is_open())
            return 1;
        std::ofstream out_privkey(privkey_file_path, std::ios::binary);
        if(!out_privkey.is_open()) {
            out_pubkey.close();
            return -1;
        }
        uint8_t gen_public_key[crypto_box_PUBLICKEYBYTES];
        uint8_t gen_private_key[crypto_box_SECRETKEYBYTES];
        crypto_box_keypair(gen_public_key, gen_private_key);
        std::copy(std::begin(gen_public_key), std::end(gen_public_key), public_key);
        std::copy(std::begin(gen_private_key), std::end(gen_private_key), private_key);
        is_empty = false;
        out_pubkey.write(reinterpret_cast<const char *>(public_key.data()), public_key.size());
        out_privkey.write(reinterpret_cast<const char *>(private_key.data()), private_key.size());
        out_pubkey.close();
        out_privkey.close();
        return 0;
    }

    int key_mgr_init(std::string& pubkey_file_path, std::string& privkey_file_path) {
        if(!is_empty) 
            return 1; // If already init.
        auto ret = load_local_key_files(pubkey_file_path, privkey_file_path);
        if(ret != 0) {
            if(gen_key_save_to_local(pubkey_file_path, privkey_file_path) != 0)
                return -1;
        }
        return 0;
    }
    const std::array<uint8_t, crypto_box_SECRETKEYBYTES>& get_private_key() const {
        return private_key;
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
    std::array<uint8_t, const_cid_bytes> client_cid;
    std::array<uint8_t, crypto_box_PUBLICKEYBYTES> client_public_key;

    // Generated
    uint64_t cinfo_hash; // Will be the unique key for unordered_map.
    std::array<uint8_t, const_sid_bytes> server_sid;
    std::array<uint8_t, crypto_aead_aes256gcm_KEYBYTES> aes256gcm_key;

    struct sockaddr_in src_addr;   // the updated source_ddress. 

    //  0 - empty
    //  1 - empty but with a random cinfo_hash
    //  2 - prepared: cid + public_key + real cinfo_hash + server_sid + AES_key
    //  3 - activated
    // -1 - recycled
    int status; 
public:
    static uint64_t hash_client_info(const std::array<uint8_t, const_cid_bytes>& client_cid, const std::array<uint8_t, crypto_box_PUBLICKEYBYTES>& client_public_key) {
        uint8_t hash[sizeof(uint64_t)];
        std::array<uint8_t, const_cid_bytes + crypto_box_PUBLICKEYBYTES> client_info;
        std::copy(client_cid.begin(), client_cid.end(), client_info.begin());
        std::copy(client_public_key.begin(), client_public_key.end(), client_info.begin() + const_cid_bytes);
        crypto_generichash(hash, sizeof(uint64_t), client_info.data(), client_info.size(), nullptr, 0);
        uint64_t ret = 0;
        for(uint8_t i = 0; i < sizeof(uint64_t); ++ i)
            ret |= (static_cast<uint64_t>(hash[i]) << (i << 3));
        return ret;
    }

    static void generate_aes_nonce(std::array<uint8_t, crypto_aead_aes256gcm_NPUBBYTES>& aes256gcm_nonce) {
        randombytes_buf(aes256gcm_nonce.data(), aes256gcm_nonce.size());
    }

    // Disable the default constructor
    session_item() : status(0) {}

    // Provide a random cinfo_hash but no client info.
    session_item(const uint64_t& precalc_cinfo_hash) : status(1) {
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
    const std::array<uint8_t, const_cid_bytes>& get_client_cid() const {
        return client_cid;
    }
    const std::array<uint8_t, const_sid_bytes>& get_server_sid() const {
        return server_sid;
    }
    const std::array<uint8_t, crypto_box_PUBLICKEYBYTES>& get_client_public_key() const {
        return client_public_key;
    }
    const int& get_session_status() const {
        return status;
    }
    bool is_session_recycled() const {
        return status == -1;
    }
    bool is_session_empty() const {
        return status == 0;
    }
    int session_prepare(std::array<uint8_t, const_cid_bytes>& recv_client_cid, std::array<uint8_t, crypto_box_PUBLICKEYBYTES>& recv_client_public_key, const curve25519_key_mgr& key_mgr, bool is_precalc_hash) {
        if(!key_mgr.is_activated())
            return -1;
        if(status != 0)
            return 1;
        client_cid = recv_client_cid;
        client_public_key = recv_client_public_key;
        if(!is_precalc_hash) 
            cinfo_hash = hash_client_info(recv_client_cid, recv_client_public_key);
        randombytes_buf(server_sid.data(), server_sid.size());
        crypto_box_beforenm(aes256gcm_key.data(), client_public_key.data(), key_mgr.get_private_key().data());
        status = 2;
        return 0;
    }
    bool session_activate() {
        if(status != 2) 
            return false;
        status = 3;
        return true;
    }
    bool session_recycle() {
        if(status != 2 && status != 3)
            return false;
        std::memset(aes256gcm_key.data(), 0, aes256gcm_key.size()); // Clear the key
        std::memset(server_sid.data(), 0, server_sid.size()); // Clear the session_sid
        status = -1;
        return true;
    }
    int session_restart(curve25519_key_mgr& key_mgr) {
        if(!key_mgr.is_activated())
            return -1;
        if(status != -1)
            return 1;
        randombytes_buf(server_sid.data(), server_sid.size());
        crypto_box_beforenm(aes256gcm_key.data(), client_public_key.data(), key_mgr.get_private_key().data());
        status = 2;
        return true;
    }
    void session_clear() {
        std::memset(client_public_key.data(), 0, client_public_key.size());
        std::memset(client_cid.data(), 0, client_cid.size());
        std::memset(server_sid.data(), 0, server_sid.size());
        std::memset(aes256gcm_key.data(), 0, aes256gcm_key.size());
        status = 0;
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

    int prepare_add_session(std::array<uint8_t, const_cid_bytes>& recv_client_cid, std::array<uint8_t, crypto_box_PUBLICKEYBYTES>& recv_client_public_key, const curve25519_key_mgr& key_mgr) {
        if(!key_mgr.is_activated())
            return -1;
        uint64_t key = session_item::hash_client_info(recv_client_cid, recv_client_public_key);
        if(sessions.find(key) != sessions.end())
            return 1;
        session_item session(key);
        session.session_prepare(recv_client_cid, recv_client_public_key, key_mgr, true);
        sessions.insert({key, session});
        ++ stats.total;
        ++ stats.prepared;
        return 0;
    }
    session_item* get_session_by_key(uint64_t key) {
        auto it = sessions.find(key);
        if(it != sessions.end())
            return &(*it).second;
        return nullptr;
    }
    const bool is_session_stored(uint64_t key) {
        return (get_session_by_key(key) != nullptr);
    }
    bool delete_session_by_key(uint64_t key) {
        auto ptr = get_session_by_key(key);
        if(ptr == nullptr)
            return false;
        auto status = ptr->get_session_status();
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
    int activate_session_by_key(uint64_t key) {
        auto ptr = get_session_by_key(key);
        if(ptr == nullptr)
            return -1;
        if(ptr->session_activate()) {
            ++ stats.active;
            -- stats.prepared;
            return 0;
        }
        return 1;
    }
};

// Connection Context contains an addr, a bind/empty uid, and a status
class session_ctx {
    std::string ctx_uid;           // Binded/Empty user unique ID
    int ctx_status;                // Connection Status

public:
    session_ctx() : ctx_status(0) {
        ctx_uid.clear();
    }
    const std::string& get_bind_uid() const {
        return ctx_uid;
    }
    const int get_status() const {
        return ctx_status;
    }
    void set_bind_uid(std::string& uid) {
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

class session_ctx_pool {
    std::unordered_map<uint64_t, session_ctx> contexts;

public:
    session_ctx_pool() {};
    session_ctx *get_ctx_by_key(const uint64_t& key) {
        auto it = contexts.find(key);
        if(it == contexts.end())
            return nullptr;
        return &(*it).second;
    }
    std::unordered_map<uint64_t, session_ctx>& get_ctx_map() {
        return contexts;
    }
    bool add_ctx_by_key(uint64_t& key) {
        if(contexts.find(key) != contexts.end())
            return false;
        contexts.emplace(key, session_ctx());
        return true;
    }
    bool delete_ctx_by_key(uint64_t& key) {
        if(contexts.find(key) == contexts.end())
            return false;
        contexts.erase(key);
        return true;
    }
};

// The user storage is in memory, no persistence. Just for demonstration.
// Please consider using a database if you'd like to go further.
class user_database {
    std::unordered_map<std::string, user_entry> user_db;
    std::string user_list_fmt;

public:
    static std::string get_pass_hash(std::string& password) {
        std::string ret;
        char hashed_pwd[crypto_pwhash_STRBYTES];
        if(crypto_pwhash_str(
            hashed_pwd, 
            password.c_str(), 
            password.size(), 
            crypto_pwhash_OPSLIMIT_INTERACTIVE, 
            crypto_pwhash_MEMLIMIT_INTERACTIVE
            ) == 0 ) {
            ret = hashed_pwd;
        };
        password.clear(); // For security reasons, we clean the string after hashing. 
        return ret;
    }
    user_entry *get_user_entry(std::string user_uid) {
        auto it = user_db.find(user_uid);
        if(it != user_db.end()) 
            return &(it->second);
        else
            return nullptr;
    }
    bool is_in_db(std::string user_uid) {
        return user_db.find(user_uid) != user_db.end();
    }

    auto get_user_num() {
        return user_db.size();
    }

    // Only Alphabet, numbers, and hyphen are allowed.
    // Length: 4-64
    static int user_uid_check(const std::string& str) {
        if(str.size() < uid_minlen || str.size() > uid_maxlen)
            return -1;
        for(auto c : str) {
            if(!std::isalnum(static_cast<unsigned char>(c)) && c != '-')
                return 1;
        }
        return 0;
    }

    // Only Alphabet, numbers, and special chars are allowed.
    // Length: 8-64
    static int pass_str_check(const std::string& pass_str) {
        if(pass_str.size() < password_minlen || pass_str.size() > password_maxlen)
            return -1;
        std::string special = std::string(special_chars);
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
            if(special.find(c) != std::string::npos) {
                contain_special_char = 1;
                continue;
            }
            return 1;
        }
        if(contain_num + contain_special_char + contain_lower_char + contain_upper_char < 3)
            return 2;
        return 0;
    }

    bool add_user(std::string user_uid, std::string user_password) {
        if(user_uid.empty() || user_password.empty())
            return false;
        if(is_in_db(user_uid))
            return false;
        struct user_entry new_user;
        new_user.user_uid = user_uid;
        new_user.pass_hash = get_pass_hash(user_password);
        if(new_user.pass_hash.empty())
            return false;
        user_db[user_uid] = new_user;
        user_list_fmt += (user_uid + " ");
        return true;
    }

    bool is_user_pass_valid(std::string user_uid, std::string& provided_password) {
        if(user_uid.empty() || provided_password.empty()) {
            provided_password.clear();
            return false;
        }
        if(!is_in_db(user_uid)) {
            provided_password.clear();
            return false;
        }
        auto ptr_user = get_user_entry(user_uid);
        if(ptr_user == nullptr) {
            provided_password.clear();
            return false;
        }
        auto ret = (crypto_pwhash_str_verify(
            (ptr_user->pass_hash).c_str(), 
            provided_password.c_str(), 
            provided_password.size()) == 0);
        provided_password.clear();
        return ret;
    }

    std::string get_user_list() {
        return user_list_fmt;
    }

    std::string get_user_list(bool show_status) {
        if(!show_status)
            return get_user_list();
        std::string list_with_status;
        for(auto& it : user_db) {
            if(it.second.user_status == 1)
                list_with_status += (it.second.user_uid + "(in) ");
            else
                list_with_status += (it.second.user_uid) + " ";
        }
        return list_with_status;
    }

    bool set_user_status(std::string user_uid, uint8_t status) {
        auto ptr = get_user_entry(user_uid);
        if(ptr == nullptr)
            return false;
        ptr->user_status = status;
        return true;
    }

    std::pair<size_t, size_t> get_user_stat() {
        size_t in = 0;
        for(auto& it : user_db) {
            if(it.second.user_status == 1)
                ++ in;
        }
        return std::make_pair(get_user_num(), in);
    }
};

struct msg_buffer {
    std::array<uint8_t, buff_size> recv_raw_buffer;
    uint16_t recv_raw_bytes;

    // A buffer to handle aes decryption
    std::array<uint8_t, buff_size> recv_aes_buffer;
    uint16_t recv_aes_bytes;

    // A buffer to send aes_encrypted messages
    std::array<uint8_t, buff_size> send_buffer;
    uint16_t send_bytes;
    const uint8_t *send_msg;

    msg_buffer() : recv_raw_bytes(0), recv_aes_bytes(0), send_bytes(0), send_msg(nullptr) {
        recv_raw_buffer = std::array<uint8_t, buff_size>();
        recv_aes_buffer = std::array<uint8_t, buff_size>();
        send_buffer = std::array<uint8_t, buff_size>();
    }

    void clear_buffer() {
        std::memset(recv_raw_buffer.data(), 0, recv_raw_bytes);
        std::memset(recv_aes_buffer.data(), 0, recv_aes_bytes);
        std::memset(send_buffer.data(), 0, send_bytes);
        recv_raw_bytes = 0;
        recv_aes_bytes = 0;
        send_bytes = 0;
        send_msg = nullptr;
    }

    bool is_recv_empty() const {
        return (recv_raw_bytes == 0);
    }
    bool is_recv_empty() const {
        return (recv_raw_bytes == 0);
    }
    bool recv_size_too_small() const {
        return (recv_raw_bytes < 1 + const_cid_bytes + crypto_box_PUBLICKEYBYTES);
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
    user_database users;            // all users
    session_pool conns;             // all sessions.
    session_ctx_pool clnts;         // all clients(contexts).
    int err_code;                   // error code
    
public:
    // A simple constructor
    udp_chatroom() {
        port = default_port;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);
        server_fd = -1;
        key_mgr = curve25519_key_mgr();
        buffer = msg_buffer();
        users = user_database();
        conns = session_pool();
        clnts = session_ctx_pool();
        err_code = 0;
    }

    // Close server and possible FD
    bool close_server(int err) {
        err_code = err;
        if(server_fd != -1) {
            close(server_fd); 
            server_fd = -1;
        }
        return err == 0;
    }

    // Get last error code
    int get_last_error(void) {
        return err_code;
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
        return (conns.get_session_by_key(cinfo_hash) != nullptr);
    }

    // Simplify the socket send function.
    int simple_send(const uint64_t& cinfo_hash, const void *msg, size_t n) {
        auto p_conn = conns.get_session_by_key(cinfo_hash);
        if(p_conn == nullptr)
            return -3; // Invalid cinfo_hash
        auto addr = p_conn->get_src_addr();
        return sendto(server_fd, msg, n, MSG_CONFIRM, (struct sockaddr *)&addr, sizeof(addr));
    }

    int notify_reset_conn(uint64_t& cinfo_hash, const void *msg, size_t size_of_msg, bool clean_client) {
        auto ret1 = simple_send(cinfo_hash, msg, size_of_msg);
        auto ret2 = simple_send(cinfo_hash, connection_reset, sizeof(connection_reset));
        int ret3 = 1;
        if(clean_client) {
            clnts.get_ctx_by_key(cinfo_hash)->clear_ctx();
        } 
        else {
            ret3 = simple_send(cinfo_hash, main_menu, sizeof(main_menu));
            clnts.get_ctx_by_key(cinfo_hash)->reset_ctx();
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
        auto map = clnts.get_ctx_map();
        for(auto it : map) {
            if(it.second.get_bind_uid() == user_uid) {
                ret = it.first; 
                return true;
            }
        }
        return false;
    }

    bool is_user_signed_in(const std::string& user_uid) {
        auto map = clnts.get_ctx_map();
        uint64_t tmp;
        return get_cinfo_by_uid(tmp, user_uid);
    }

    /* Broadcasting to all connected clients (include or exclude current/self).
    size_t system_broadcasting(bool include_self, uint64_t self_cinfo, std::string& raw_msg_body) {
        auto ptr = clnts.get_ctx_by_key(self_cinfo);
        if(ptr == nullptr && self_cinfo)
            return 0; // Invalid source client_info
        std::string msg = "[SYSTEM_BROADCAST]: [UID]";
        msg += ptr->get_bind_uid();
        size_t sent_out = 0;
        for(auto elem : clnts.get_ctx_map()) {
            if(elem.second.get_status() != 6)
                continue;
            if(elem.second.get_bind_uid() == ptr->get_bind_uid() && !include_self)
                continue;
            if(simple_send(elem.first, msg.data(), msg.size()) >= 0)
                ++ sent_out;
        }
        return sent_out;
    }*/
    
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

    // Main processing method.
    int run_server(void) {
        if(server_fd == -1) {
            std::cout << "Server not started." << std::endl;
            return -1;
        }
        ctx_user_bind_buffer bind_buffer;
        while(true) {
            struct sockaddr_in client_addr;
            auto addr_len = 
            buffer.clear_buffer();
            auto bytes_recv = recvfrom(server_fd, buffer.recv_raw_buffer.data(), buffer.recv_raw_buffer.size(), MSG_WAITALL, (struct sockaddr *)&client_addr, (socklen_t *)&addr_len);
            auto bytes_recv = recvfrom(server_fd, buffer.data(), buffer.size(), \
                MSG_WAITALL, (struct sockaddr *)&client_addr, (socklen_t *)&addr_len);
            if(bytes_recv < 0)
                return close_server(-3);
            buffer[bytes_recv - 1] = '\0'; // Omit the '\n' char.
            std::string buff_str = buffer.data();
            std::cout << ">> Received from: " << std::endl << inet_ntoa(client_addr.sin_addr) \
                      << ':' << ntohs(client_addr.sin_port) << '\t' << buffer.data() << std::endl;
            auto conn_idx = get_conn_idx(client_addr);

            // New connection, initialize it.
            if(conn_idx == clients.size()) {
                conn_ctx new_conn;
                new_conn.set_conn_addr(client_addr);
                simple_send(main_menu, sizeof(main_menu), client_addr);
                new_conn.set_status(1);
                clients.push_back(new_conn);
                continue;
            }

            // conn_idx is valid. Start processing.
            auto& client = clients[conn_idx];
            auto stat = client.get_status();
            if(stat == 0) {
                simple_send(main_menu, sizeof(main_menu), client_addr);
                client.set_status(1);
                continue;
            }
            if(stat == 100) { // Waiting for yes or no
                if(buff_str != "yes" && buff_str != "no") {
                    notify_reset_conn(not_yes_or_no, sizeof(not_yes_or_no), client, false);
                    continue;
                }
                if(buff_str == "yes") {
                    simple_send(input_password, sizeof(input_password), client_addr);
                    simple_send(another_sign_warn, sizeof(another_sign_warn), *(clients[bind_buffer.get_prev_ctx_idx()].get_conn_addr()));
                    client.set_bind_uid(bind_buffer.get_user_uid());
                    client.set_status(5);
                }
                else {
                    notify_reset_conn(option_denied, sizeof(option_denied), client, false);
                }
                continue;
            }
            if(stat == 1) {
                if(buff_str != "1" && buff_str != "2") {
                    notify_reset_conn(option_error, sizeof(option_error), client, false);
                    continue;
                }
                if(buff_str == "1") {
                    simple_send(input_username, sizeof(input_username), client_addr);
                    client.set_status(2); // Sign up
                }
                else {
                    simple_send(input_username, sizeof(input_username), client_addr);
                    client.set_status(3); // Sign in
                }
                continue;
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
