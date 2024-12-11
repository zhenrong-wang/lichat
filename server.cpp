// This is the *simplest* UDP (Message based) echo server in C++ for learning
// Originally written by Zhenrong WANG (zhenrongwang@live.com | X/Twitter: @wangzhr4)
// Prerequisites: libsodium. You need to install it before compiling this code
// Compile: g++ udp_chatroom.cpp -lsodium

#include "lc_keymgr.hpp"
#include "lc_consts.hpp"
#include "lc_bufmgr.hpp"
#include "lc_sesmgr.hpp"

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
#include <iomanip>

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
    bool clear_ctx_by_uid(const std::string& uid, uint64_t& cif) {
        for(auto& elem : contexts) {
            if(elem.second.get_bind_uid() == uid) {
                elem.second.clear_ctx();
                cif = elem.first;
                return true;
            }
        }
        return false;
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

    static bool pass_hash(std::string& password, std::array<char, crypto_pwhash_STRBYTES>& hashed_pwd) {
        auto ret = 
        crypto_pwhash_str(
            hashed_pwd.data(), 
            password.c_str(), 
            password.size(), 
            crypto_pwhash_OPSLIMIT_INTERACTIVE, 
            crypto_pwhash_MEMLIMIT_INTERACTIVE
        );
        password.clear(); // For security reasons, we clean the string after hashing.
        if(ret == 0)
            return true;
        return false;
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
        crypto_hash_sha256(sha256_hash, reinterpret_cast<const unsigned char *>(valid_email.c_str()), valid_email.size());
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

    // Have to use pointer to avoid exception handling.
    const std::string* get_uname_by_uemail(const std::string& uemail) {
        auto it = user_db.find(uemail);
        if(it == user_db.end())
            return nullptr;
        return &(it->second.unique_name);
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
        std::array<char, crypto_pwhash_STRBYTES> hashed_pass;
        if(!pass_hash(user_password, hashed_pass)) {
            err = 9;
            return false;
        }
        if(is_username_occupied(uname)) {
            if(!randomize_username(uname)) {
                err = 11;
                return false;
            }
        }
        struct user_item new_user;
        new_user.unique_email = uemail;
        new_user.unique_id = email_to_uid(uemail);
        new_user.unique_name = uname;
        new_user.pass_hash = hashed_pass;
        user_db.insert({uemail, new_user});
        uname_uemail.insert({uname, uemail});
        user_list_fmt += (uname + " (" + uemail + ") " + "\n");
        return true;
    }

    // type = 0: uemail + password
    // type = 1 (or others): uname + password
    bool user_pass_check(const uint8_t type, const std::string& str, std::string& password, uint8_t& err) {
        user_item *ptr_item = nullptr;
        err = 0;
        if(type == 0x00) {
            if(!is_email_registered(str)) {
                err = 2;
                password.clear();
                return false;
            }
            ptr_item = get_user_item_by_uemail(str);
        }
        else {
            if(!is_username_occupied(str)) {
                err = 4;
                password.clear();
                return false;
            }
            ptr_item = get_user_item_by_uname(str);
        }
        if(ptr_item == nullptr) {
            err = 6;
            password.clear();
            return false;
        }
        auto ret = (crypto_pwhash_str_verify(
            (ptr_item->pass_hash).data(), 
            password.c_str(), 
            password.size()) == 0);

        password.clear();
        if(!ret) err = 8;
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
    bool set_user_status(const uint8_t type, const std::string& str, const uint8_t status) {
        user_item *ptr_item = nullptr;
        if(type == 0x00) 
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

// The main class.
class lichat_server {
    struct sockaddr_in server_addr;                 // socket addr
    uint16_t server_port;                           // port number
    int server_fd;                                  // generated server_fd
    std::pair<std::string, std::string> key_paths;  // public_key secret_key
    curve25519_key_mgr key_mgr;                     // key manager
    msg_buffer buffer;                              // Message core processor
    user_mgr users;                                 // all users
    session_pool conns;                             // all sessions.
    ctx_pool clients;                               // all clients(contexts).
    int last_error;                                 // error code
    
public:
    // A simple constructor
    lichat_server() {
        server_port = DEFAULT_SERVER_PORT;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(server_port);
        server_fd = -1;
        key_paths = std::make_pair(default_server_pk, default_server_sk);
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
        if(key_mgr.key_mgr_init(key_paths.first, key_paths.second) != 0) {
            std::cout << "Key manager not activated." << std::endl;
            return close_server(1);
        }
        server_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if(server_fd == -1)
            return close_server(3);
        if(bind(server_fd, (sockaddr *)&server_addr, (socklen_t)sizeof(server_addr)))
            return close_server(5);
        std::cout << "UDP Chatroom Service started." << std::endl 
                  << "UDP Listening Port: " << server_port << std::endl;
        return true;
    }

    bool is_session_valid(const uint64_t& cinfo_hash) {
        return (conns.get_session(cinfo_hash) != nullptr);
    }

    // Simplify the socket send function.
    int simple_send(const uint64_t& cinfo_hash, const uint8_t *msg, size_t n) {
        auto p_conn = conns.get_session(cinfo_hash);
        if(p_conn == nullptr)
            return -3; // Invalid cinfo_hash
        auto addr = p_conn->get_src_addr();
        return sendto(server_fd, msg, n, MSG_CONFIRM, (struct sockaddr *)&addr, sizeof(addr));
    }

    // Simplify the socket send function.
    int simple_send(const struct sockaddr_in& addr, const uint8_t *msg, size_t n) {
        return sendto(server_fd, msg, n, MSG_CONFIRM, (struct sockaddr *)&addr, sizeof(addr));
    }

    // Simplify the socket send function.
    int simple_send(uint8_t header, const struct sockaddr_in& addr, const uint8_t *msg, size_t n) {
        if(n + 1 > buffer.send_buffer.size()) {
            return -3;
        }
        buffer.send_buffer[0] = header;
        std::copy(msg, msg + n, buffer.send_buffer.begin() + 1);
        buffer.send_bytes = n + 1;
        return sendto(server_fd, buffer.send_buffer.data(), buffer.send_bytes, MSG_CONFIRM, (struct sockaddr *)&addr, sizeof(addr));
    }

    // Simplify the socket send function.
    // Format : 1-byte header + 
    //          if 0x00 header, add a 32byte pubkey, otherwise skip + 
    //          aes_nonce + 
    //          aes_gcm_encrypted (sid + cinfo_hash + msg_body)
    int simple_secure_send(const uint8_t header, const std::array<uint8_t, crypto_aead_aes256gcm_KEYBYTES>& aes_key, const struct sockaddr_in& addr, const std::array<uint8_t, SID_BYTES>& sid, std::array<uint8_t, CIF_BYTES>& cif, const curve25519_key_mgr& key_mgr, const uint8_t *raw_msg, size_t raw_n) {
        std::array<uint8_t, crypto_aead_aes256gcm_NPUBBYTES> server_aes_nonce;
        size_t offset = 0, aes_encrypted_len = 0;

        // Padding the first byte
        buffer.send_buffer[0] = header;
        ++ offset;
        
        if(header == 0x00) {
            auto server_public_key = key_mgr.get_public_key();
            std::copy(server_public_key.begin(), server_public_key.end(), buffer.send_buffer.begin() + offset);
            offset += server_public_key.size();
        }
    
        // Padding the aes_nonce
        session_item::generate_aes_nonce(server_aes_nonce);
        std::copy(server_aes_nonce.begin(), server_aes_nonce.end(), buffer.send_buffer.begin() + offset);
        offset += server_aes_nonce.size();

        if((offset + sid.size() + cif.size() + raw_n + crypto_aead_aes256gcm_ABYTES) > BUFF_SIZE) {
            buffer.send_bytes = offset;
            return -1; // buffer overflow occur.
        }

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
            return -3;
        auto ret = simple_send(addr, buffer.send_buffer.data(), buffer.send_bytes);
        if(ret < 0) 
            return -5;
        return ret;
    }

    int notify_reset_conn(uint64_t& cinfo_hash, const uint8_t *msg, size_t size_of_msg, bool clean_client) {
        auto ret1 = simple_send(cinfo_hash, msg, size_of_msg);
        auto ret2 = simple_send(cinfo_hash, reinterpret_cast<const uint8_t *>(connection_reset), sizeof(connection_reset));
        int ret3 = 1;
        if(clean_client) {
            clients.get_ctx(cinfo_hash)->clear_ctx();
        } 
        else {
            ret3 = simple_send(cinfo_hash, reinterpret_cast<const uint8_t *>(main_menu), sizeof(main_menu));
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

    // Broadcasting to all connected clients (include or exclude current/self).
    size_t system_secure_broadcasting(bool include_self, std::string uemail, uint8_t header, const uint8_t *raw_msg, size_t raw_n) {
        std::string msg = "[SYSTEM_BROADCAST]: [UID]";
        auto ptr_uname = users.get_uname_by_uemail(uemail);
        if(ptr_uname == nullptr)
            return 0;
        msg += (*ptr_uname);
        std::string msg_str(reinterpret_cast<const char *>(raw_msg), raw_n);
        msg += msg_str;
        size_t sent_out = 0;
        for(auto elem : clients.get_ctx_map()) {
            if(elem.second.get_status() != 2)
                continue;
            if(elem.second.get_bind_uid() == uemail && !include_self)
                continue;
            auto cif = elem.first;
            session_item *ptr_session = conns.get_session(cif);
            if(ptr_session == nullptr)
                continue;
            auto aes_key = ptr_session->get_aes_gcm_key();
            auto addr = ptr_session->get_src_addr();
            auto sid = ptr_session->get_server_sid();
            auto cif_bytes = session_item::u64_to_bytes(cif);
            if(simple_secure_send(header, aes_key,  addr, sid, cif_bytes, key_mgr, raw_msg, raw_n) >= 0)
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
        if(!key_mgr.is_activated()) {
            std::cout << "Key manager not activated." << std::endl;
            return 1;
        }
        if(server_fd == -1) {
            std::cout << "Server not started." << std::endl;
            return 3;
        }
        
        auto server_public_key = key_mgr.get_public_key();
        std::array<uint8_t, crypto_aead_aes256gcm_NPUBBYTES> client_aes_nonce;
        size_t aes_encrypted_len = 0;
        size_t aes_decrypted_len = 0;
        while(true) {
            struct sockaddr_in client_addr;
            auto addr_len = sizeof(client_addr);
            buffer.clear_buffer();
            auto bytes_recv = recvfrom(server_fd, buffer.recv_raw_buffer.data(), buffer.recv_raw_buffer.size(), MSG_WAITALL, (struct sockaddr *)&client_addr, (socklen_t *)&addr_len);
            buffer.recv_raw_bytes = bytes_recv;
            if(buffer.recved_insuff_bytes(SERVER_RECV_MIN_BYTES) || buffer.recved_overflow()) {
                std::cout << "Received message size invalid." << std::endl;
                continue; // If size is invalid, ommit.
            }
                
            std::cout << ">> Received from: " << std::endl << inet_ntoa(client_addr.sin_addr) \
                      << ':' << ntohs(client_addr.sin_port) << '\t';
            std::cout << std::endl << std::hex << std::setw(2) << std::setfill('0');
            for(size_t i = 0; i < bytes_recv; ++ i) {
                std::cout << (int)buffer.recv_raw_buffer[i] << ' ';
            }
            std::cout << std::dec << bytes_recv << std::endl;
            
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
                    return 127;
                }
                this_conn->set_src_addr(client_addr);
                auto aes_key = this_conn->get_aes_gcm_key();
                auto sid = this_conn->get_server_sid();
                auto cinfo_hash_bytes = session_item::u64_to_bytes(cinfo_hash);
                if(header == 0x00)
                    simple_secure_send(0x00, aes_key, client_addr, sid, cinfo_hash_bytes, key_mgr, ok, sizeof(ok));
                else
                    simple_secure_send(0x01, aes_key, client_addr, sid, cinfo_hash_bytes, key_mgr, ok, sizeof(ok));
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
                
                auto cinfo_hash = session_item::bytes_to_u64(cinfo_hash_bytes);
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
                        buffer.recv_aes_buffer.begin(), (unsigned long long *)(&aes_decrypted_len),
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
                    simple_secure_send(0x02, aes_key, client_addr, server_sid, cinfo_hash_bytes, key_mgr, ok, sizeof(ok));
                    continue;
                }
                if(!is_aes_ok) 
                    std::copy(std::begin(server_ef_keyerr), std::end(server_ef_keyerr), buffer.send_buffer.begin());
                else
                    std::copy(std::begin(server_df_msgerr), std::end(server_df_msgerr), buffer.send_buffer.begin());
                std::copy(cinfo_hash_bytes.begin(), cinfo_hash_bytes.end(),  buffer.send_buffer.begin() + ERR_CODE_BYTES + 1);
                std::copy(server_public_key.begin(), server_public_key.end(), buffer.send_buffer.begin() + ERR_CODE_BYTES + 1 + cinfo_hash_bytes.size());
                buffer.send_bytes = ERR_CODE_BYTES + 1 + cinfo_hash_bytes.size(), server_public_key.size();
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

                auto cinfo_hash = session_item::bytes_to_u64(cinfo_hash_bytes);
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
                        buffer.recv_aes_buffer.begin(), (unsigned long long *)(&aes_decrypted_len),
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
                    // option: 0 - signup, 1 - signin

                    if(option != 0x00 && option != 0x01) 
                        continue; // Invalid option

                    if(option == 0x00) { // Signing up.
                        if(msg_size < 1 + 1 + ULOGIN_MIN_BYTES + 1 + ULOGIN_MIN_BYTES + 1 + PASSWORD_MIN_BYTES + 1)
                            continue; // Invalid length.

                        auto reg_info = msg_buffer::split_buffer_by_null(msg_body + 2, msg_size - 2, 3);
                        if(reg_info.size() < 3) 
                            continue; // Invalid format.

                        uint8_t err = 0;
                        if(!users.add_user(reg_info[0], reg_info[1], reg_info[2], err)) {
                            simple_secure_send(0x10, aes_key, client_addr, server_sid, cinfo_hash_bytes, key_mgr, &err, 1);
                            continue;
                        }
                        const char msg[] = " signed up and signed in!\n";
                        system_secure_broadcasting(false, reg_info[0], 0x10, reinterpret_cast<const uint8_t *>(msg), sizeof(msg));
                        this_client->set_bind_uid(reg_info[0]);
                        this_client->set_status(2);
                        users.set_user_status(0, reg_info[0], 1);
                        continue;
                    }
                    // Processing sign in process. signin_type = 0: uemail, signin_type = 1: uname;
                    auto signin_type = msg_body[1];
                    if(signin_type != 0x00 && signin_type != 0x01) 
                        continue;

                    auto signin_info = msg_buffer::split_buffer_by_null(msg_body + 2, msg_size - 2, 2);
                    if(signin_info.size() < 2)
                        continue;
                    
                    uint8_t err = 0;
                    // signin_info[0]: uemail or uname, signin_info[1]: password
                    if(!users.user_pass_check(signin_type, signin_info[0], signin_info[1], err)) {
                        simple_secure_send(0x10, aes_key, client_addr, server_sid, cinfo_hash_bytes, key_mgr, &err, 1);
                        continue;
                    }
                    const char msg[] = " signed in!\n";
                    std::string uname, uemail;
                    uint64_t cif;
                    if(signin_type == 0x00) {
                        uemail = signin_info[0];
                        uname = *(users.get_uname_by_uemail(signin_info[0]));
                    }
                    else {
                        uemail = *(users.get_uemail_by_uname(signin_info[0]));
                        uname = signin_info[0];
                    }
                    
                    uint64_t prev_cif;
                    if(clients.clear_ctx_by_uid(uemail, prev_cif)) {
                        const char auto_signout[] = "You've been signed in on another session. Signed out here.\n";
                        auto ptr_prev = conns.get_session(cif);
                        auto cif_bytes = session_item::u64_to_bytes(cif);
                        if(ptr_prev != nullptr) {
                            simple_secure_send(0x10, 
                                ptr_prev->get_aes_gcm_key(), 
                                ptr_prev->get_src_addr(), 
                                ptr_prev->get_server_sid(), 
                                cif_bytes, key_mgr, reinterpret_cast<const uint8_t *>(auto_signout), sizeof(auto_signout));
                        };
                    }                    
                    this_client->set_bind_uid(uemail);
                    this_client->set_status(2);
                    users.set_user_status(0, uemail, 1);
                    system_secure_broadcasting(false, uemail, 0x10, reinterpret_cast<const uint8_t *>(msg), sizeof(msg));
                    continue;
                }
                system_secure_broadcasting(true, this_client->get_bind_uid(), 0x10, msg_body, msg_size);
            }
        }
    }
};

// The simplest driver. You can improve it if you'd like to go further.
int main(int argc, char **argv) {
    lichat_server new_server;
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