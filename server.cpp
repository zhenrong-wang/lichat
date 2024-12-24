// This is the *simplest* UDP (Message based) echo server in C++ for learning
// Originally written by Zhenrong WANG (zhenrongwang@live.com | X/Twitter: @wangzhr4)
// Prerequisites: libsodium. You need to install it before compiling this code
// Compile: g++ udp_chatroom.cpp -lsodium

#include "lc_keymgr.hpp"
#include "lc_consts.hpp"
#include "lc_bufmgr.hpp"
#include "lc_common.hpp"

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
#include <thread>
#include <thread>
#include <ctime>
#include <fstream>
#include <regex>
#include <random>
#include <iomanip>

enum SERVER_ERRORS {
    NORMAL_RETURN = 0,
    KEYMGR_FAILED,
    USERDB_PRECHECK_FAILED,
    SOCK_FD_INVALID,
    SOCK_BIND_FAILED,
    SET_TIMEOUT_FAILED,
    INTERNAL_FATAL,
    MSG_SIGNING_FAILED
};

// We use AES256-GCM algorithm here
class session_item {
    // Received
    std::array<uint8_t, CID_BYTES> client_cid;
    std::array<uint8_t, crypto_box_PUBLICKEYBYTES> client_public_key;
    std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> client_sign_key;

    // Generated
    uint64_t cinfo_hash; // Will be the unique key for unordered_map.
    std::array<uint8_t, SID_BYTES> server_sid;
    std::array<uint8_t, crypto_aead_aes256gcm_KEYBYTES> aes256gcm_key;

    struct sockaddr_in src_addr;   // the updated source_ddress.
    time_t last_heartbeat;

    //  0 - empty
    //  1 - prepared: cid + public_key + real cinfo_hash + server_sid + AES_key
    //  2 - activated
    int status; 
public:
    // Disable the default constructor
    session_item () : status(0) {}

    // Provide a random cinfo_hash but no client info.
    session_item (const uint64_t& precalc_cinfo_hash) : status(0) {
        cinfo_hash = precalc_cinfo_hash;
    }

    const struct sockaddr_in& get_src_addr () const {
        return src_addr;
    }
    void set_src_addr (const sockaddr_in& addr) {
        src_addr = addr;
    }
    const std::array<uint8_t, crypto_aead_aes256gcm_KEYBYTES>& 
        get_aes_gcm_key () const {

        return aes256gcm_key;
    }
    const std::array<uint8_t, CID_BYTES>& get_client_cid () const {
        return client_cid;
    }
    const std::array<uint8_t, SID_BYTES>& get_server_sid () const {
        return server_sid;
    }
    const std::array<uint8_t, crypto_box_PUBLICKEYBYTES>& 
        get_client_public_key () const {

        return client_public_key;
    }
    const std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>& 
        get_client_sign_key () const {

        return client_sign_key;
    }
    const int& get_status () const {
        return status;
    }
    int prepare (std::array<uint8_t, CID_BYTES>& recv_client_cid, 
        std::array<uint8_t, crypto_box_PUBLICKEYBYTES>& recv_client_public_key, 
        std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>& recv_client_sign_key, 
        const key_mgr_25519& key_mgr, bool is_precalc_hash) {

        if (!key_mgr.is_activated())
            return -1;
        if (status != 0)
            return 1;
        std::array<uint8_t, crypto_aead_aes256gcm_KEYBYTES> calc_aes_key;
        if (crypto_box_beforenm(calc_aes_key.data(), 
            recv_client_public_key.data(), 
            key_mgr.get_crypto_sk().data()) != 0)
            return 3;

        client_cid = recv_client_cid;
        client_public_key = recv_client_public_key;
        client_sign_key = recv_client_sign_key;
        aes256gcm_key = calc_aes_key;
        if (!is_precalc_hash) 
            cinfo_hash = lc_utils::hash_client_info(recv_client_cid, 
                         recv_client_public_key);
        randombytes_buf(server_sid.data(), server_sid.size());
        status = 1;
        return 0;
    }
    bool activate () {
        if (status != 1) 
            return false;
        status = 2;
        return true;
    }
    const time_t& get_last_heartbeat () {
        return last_heartbeat;
    }
    void set_last_heartbeat (time_t t) {
        last_heartbeat = t;
    }
    bool is_inactive () {
        if (lc_utils::now_time() - last_heartbeat > HEARTBEAT_TIMEOUT_SECS) 
            return true;
        else 
            return false;
    }
    bool is_inactive (time_t now) {
        if (now - last_heartbeat > HEARTBEAT_TIMEOUT_SECS) 
            return true;
        else 
            return false;
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

    uint64_t gen_64bit_key () {
        std::array<uint8_t, 8> hash_key;
        randombytes_buf(hash_key.data(), hash_key.size());
        uint64_t ret = 0;
        for (uint8_t i = 0; i < 8; ++ i)
            ret |= (static_cast<uint64_t>(hash_key[i]) << (i * 8));
        return ret;
    }

public:
    session_pool () : stats({0, 0, 0, 0, 0}) {};

    int prepare_add_session(std::array<uint8_t, CID_BYTES>& recv_client_cid, 
        std::array<uint8_t, crypto_box_PUBLICKEYBYTES>& recv_client_public_key, 
        std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>& recv_client_sign_key, 
        const key_mgr_25519& key_mgr) {

        if (!key_mgr.is_activated())
            return -1;
        uint64_t key = lc_utils::hash_client_info(recv_client_cid, 
                                                recv_client_public_key);
        if (sessions.find(key) != sessions.end())
            return 1;
        session_item session(key);
        session.prepare(recv_client_cid, recv_client_public_key, 
                        recv_client_sign_key, key_mgr, true);
        sessions.insert({key, session});
        ++ stats.total;
        ++ stats.prepared;
        return 0;
    }
    session_item* get_session (uint64_t key) {
        auto it = sessions.find(key);
        if (it != sessions.end())
            return &(*it).second;
        return nullptr;
    }
    const bool is_session_stored (uint64_t key) {
        return (get_session(key) != nullptr);
    }

    void update_stats_at_session_delete (int status) {
        -- stats.total;
        if (status == 0 || status == 1)
            -- stats.empty;
        else if (status == 2)
            -- stats.prepared;
        else if (status == 3)
            -- stats.active;
        else
            -- stats.recycled;
    }

    bool delete_session (uint64_t key) {
        auto ptr = get_session(key);
        if (ptr == nullptr)
            return false;
        auto status = ptr->get_status();
        sessions.erase(key);
        update_stats_at_session_delete(status);
        return true;
    }
    int activate_session (uint64_t key) {
        auto ptr = get_session(key);
        if (ptr == nullptr)
            return -1;
        if (ptr->activate()) {
            ++ stats.active;
            -- stats.prepared;
            return 0;
        }
        return 1;
    }
    std::unordered_map<uint64_t, session_item>& get_session_map () {
        return sessions;
    }
    struct session_pool_stats& get_stats () {
        return stats;
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
    ctx_item () : ctx_status(0) {
        ctx_uid.clear();
    }
    const std::string& get_bind_uid () const {
        return ctx_uid;
    }
    const int get_status () const {
        return ctx_status;
    }
    void set_bind_uid (const std::string& uid) {
        ctx_uid = uid;
    }
    void set_status (int status) {
        ctx_status = status;
    }
    void reset_ctx () { // Go back to status 1
        ctx_uid.clear();
        ctx_status = 1;
    }
    void clear_ctx () { // Clear everything
        ctx_uid.clear();
        ctx_status = 0;
    }
};

class ctx_pool {
    std::unordered_map<uint64_t, ctx_item> contexts;

public:
    ctx_pool () {};
    ctx_item *get_ctx (const uint64_t& key) {
        auto it = contexts.find(key);
        if (it == contexts.end())
            return nullptr;
        return &(*it).second;
    }
    std::unordered_map<uint64_t, ctx_item>& get_ctx_map () {
        return contexts;
    }
    bool add_ctx (uint64_t& key) {
        if (contexts.find(key) != contexts.end())
            return false;
        contexts.emplace(key, ctx_item());
        return true;
    }
    bool delete_ctx (uint64_t& key) {
        if (contexts.find(key) == contexts.end())
            return false;
        contexts.erase(key);
        return true;
    }
    bool is_valid_ctx (uint64_t& key) {
        return (contexts.find(key) != contexts.end());
    }
    bool clear_ctx_by_uid (const uint64_t& this_cif, const std::string& uid, 
        uint64_t& cif) {
        for (auto& elem : contexts) {
            if (elem.second.get_bind_uid() == uid && elem.first != this_cif) {
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
    std::string unique_name;    // User self specified id. e.g.
    std::array<char, crypto_pwhash_STRBYTES> pass_hash;      // Hashed password
    uint8_t user_status;        // Currently, 0 - not in, 1 - signed in.
    uint64_t bind_cif;
};


// The user storage is in memory, no persistence. Just for demonstration.
// Please consider using a database if you'd like to go further.
class user_mgr {
    std::string db_file_path;
    // key: unique_email
    // value: user_item
    std::unordered_map<std::string, struct user_item> user_db;

    // key: unique_unames
    // value: unique_email
    std::unordered_map<std::string, std::string> uname_uemail;
    std::string user_list_fmt;

public:
    user_mgr () {}

    user_mgr (const std::string& path) : db_file_path(path) {}

    // Return 0: db_file_path is good to read/write
    // Return 1 or 3: db_file_path is not good to read/write
    int precheck_user_db () {
        if (db_file_path.empty())
            db_file_path = default_user_db_path;
        std::ifstream file_in(db_file_path, 
                              std::ios::in | std::ios::binary);
        if (!file_in.is_open()) {
            // Create a file.
            std::ofstream file_out(db_file_path, std::ios::binary);
            if (!file_out.is_open())
                return 1;  // Failed to create a db file.
            // Write the headers into it.
            file_out.write(user_db_header.data(), user_db_header.size());
            file_out.close();
            return 0;
        }
        // If the file is good to open, check the format.
        std::vector<char> vec(user_db_header.size());
        file_in.read(vec.data(), user_db_header.size());
        std::streamsize bytes_read = file_in.gcount();
        if (bytes_read != user_db_header.size()) {
            std::cout << bytes_read << "  " << user_db_header.size();
            return 3;
        }
               // The header is incorrect.
        std::string header_str(vec.begin(), vec.begin() + vec.size());
        if (header_str != user_db_header)
            return 5;   // The header is incorrect.
        file_in.close();
        return 0;   // The file is good to go.
    }

    int preload_user_db (size_t& loaded) {
        if (user_db.size() > 0)
            return 1;   // This operation is only valid at the beginning of the running. 

        if (precheck_user_db() != 0)
            return 3;   // Failed to precheck the db file.

        std::ifstream file_in(db_file_path, 
                              std::ios::in | std::ios::binary);
        if (!file_in.is_open())
            return 5;   // File I/O Error.
        std::streampos skip = user_db_header.size();
        file_in.seekg(skip, std::ios::beg);
        if (!file_in) 
            return 7;   // Not a valid file format.
        bool fread_error = false;
        size_t load_items = 0;
        while (true) {
            uint8_t uemail_bytes;
            uint8_t uname_bytes;
            std::array<char, crypto_pwhash_STRBYTES> passhash_read;
            file_in.read(reinterpret_cast<char *>(&uemail_bytes), 1);
            if (file_in.gcount() != 1) {
                if (file_in.eof())
                    break;
                else {
                    fread_error = true;
                    break;
                }
            }
            // Uemail length is 4~256, but uint8_t is 0~255, so we need to
            // minus 1 when write it, and plus 1 when read it.
            size_t uemail_read_bytes = static_cast<size_t>(uemail_bytes) + 1;
            std::vector<char> uemail_read(uemail_read_bytes);
            file_in.read(uemail_read.data(), uemail_read.size());
            if (file_in.gcount() != uemail_read_bytes) {
                fread_error = true;
                break;
            }
            // Uname length is the read bytes, no offset.
            file_in.read(reinterpret_cast<char *>(&uname_bytes), 1);
            if (file_in.gcount() != 1) {
                fread_error = true;
                break;
            }
            std::vector<char> uname_read(uname_bytes);
            file_in.read(uname_read.data(), uname_read.size());
            if (file_in.gcount() != uname_bytes) {
                fread_error = true;
                break;
            }
            file_in.read(passhash_read.data(), passhash_read.size());
            if (file_in.gcount() != passhash_read.size()) {
                fread_error = true;
                break;
            }
            std::string uemail_str(uemail_read.begin(), 
                                   uemail_read.begin() + uemail_read.size());
            std::string uname_str(uname_read.begin(),
                                  uname_read.begin() + uname_read.size());
            if (lc_utils::email_fmt_check(uemail_str) != 0)
                continue;
            if (lc_utils::user_name_fmt_check(uname_str) != 0)
                continue;
            if (user_db.find(uemail_str) != user_db.end())
                continue;
            if (uname_uemail.find(uname_str) != uname_uemail.end())
                continue;
            struct user_item new_user;
            new_user.unique_email = uemail_str;
            new_user.unique_name = uname_str;
            new_user.pass_hash = passhash_read;
            user_db.insert({uemail_str, new_user});
            uname_uemail.insert({uname_str, uemail_str});
            ++ load_items;
        }
        file_in.close();
        loaded = load_items;
        if (fread_error)
            return 9;
        return 0;
    }

    bool is_email_registered (const std::string& email) {
        return (user_db.find(email) != user_db.end());
    }

    static std::string email_to_uid (const std::string& valid_email) {
        uint8_t sha256_hash[crypto_hash_sha256_BYTES];
        crypto_hash_sha256(sha256_hash, 
            reinterpret_cast<const unsigned char *>(valid_email.c_str()), 
            valid_email.size());

        char b64_cstr[crypto_hash_sha256_BYTES * 2];
        sodium_bin2base64(b64_cstr, crypto_hash_sha256_BYTES * 2, sha256_hash, 
                            crypto_hash_sha256_BYTES, 
                            sodium_base64_VARIANT_ORIGINAL);

        return std::string(b64_cstr);
    }

    // If the provided username is duplicated, try randomize it with a suffix
    // The suffix comes from a random 6-byte block (2 ^ 48 possibilities)
    // If the username is still duplicate after randomization, return false
    // else return true.
    bool randomize_username (std::string& uname) {
        uint8_t random_suffix3[3], random_suffix6[6], random_suffix9[9];
        auto check = [](std::string& str, uint8_t *bytes, size_t n) {
            size_t b64_size = sodium_base64_encoded_len(n, 
                                sodium_base64_VARIANT_URLSAFE_NO_PADDING);

            std::vector<char> b64_cstr(b64_size);
            std::string new_name;
            randombytes_buf(bytes, n);
            sodium_bin2base64(b64_cstr.data(), b64_size, 
                bytes, n, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
            if (str.size() + 1 + b64_size > UNAME_MAX_BYTES) {
                auto pos = UNAME_MAX_BYTES - 1 - b64_size;
                new_name = str.substr(0, pos) + "-" + std::string(b64_cstr.data());
            }
            else {
                new_name = str + "-" + std::string(b64_cstr.data());
            }
            return new_name;
        };
        // First try.
        std::string new_name;
        new_name = check(uname, random_suffix3, sizeof(random_suffix3));
        if (!is_username_occupied(new_name)) {
            uname = new_name;
            return true;
        }
        new_name = check(uname, random_suffix6, sizeof(random_suffix6));
        if (!is_username_occupied(new_name)) {
            uname = new_name;
            return true;
        }
        new_name = check(uname, random_suffix9, sizeof(random_suffix9));
        if (!is_username_occupied(new_name)) {
            uname = new_name;
            return true;
        }
        return false;
    }

    bool is_username_occupied (const std::string& uname) {
        return (uname_uemail.find(uname) != uname_uemail.end());
    }

    // Have to use pointer to avoid exception handling.
    const std::string* get_uemail_by_uname (const std::string& uname) {
        auto it = uname_uemail.find(uname);
        if (it == uname_uemail.end())
            return nullptr;
        return &(it->second);
    }

    // Have to use pointer to avoid exception handling.
    const std::string* get_uname_by_uemail (const std::string& uemail) {
        auto it = user_db.find(uemail);
        if (it == user_db.end())
            return nullptr;
        return &(it->second.unique_name);
    }

    user_item* get_user_item_by_uemail (const std::string& uemail) {
        auto it = user_db.find(uemail);
        if (it == user_db.end())
            return nullptr;
        return &(it->second);
    }

    user_item* get_user_item_by_uname (const std::string& uname) {
        auto uemail_ptr = get_uemail_by_uname(uname);
        if (uemail_ptr == nullptr)
            return nullptr;
        return get_user_item_by_uemail(*uemail_ptr);
    }

    auto get_total_user_num () {
        return user_db.size();
    }

    bool add_user (const std::string& uemail, std::string& uname, 
        std::string& user_password, uint8_t& err, bool& is_uname_randomized) {
        
        err = 0;
        is_uname_randomized = false;
        if (lc_utils::email_fmt_check(uemail) != 0) {
            err = 1;
            return false;
        }
        if (is_email_registered(uemail)) {
            err = 3;
            return false;
        }
        if (lc_utils::user_name_fmt_check(uname) != 0) {
            err = 5;
            return false;
        }
        if (lc_utils::pass_fmt_check(user_password) != 0) {
            err = 7;
            return false;
        }
        std::array<char, crypto_pwhash_STRBYTES> hashed_pass;
        if (!lc_utils::pass_hash_secure(user_password, hashed_pass)) {
            err = 9;
            return false;
        }
        if (is_username_occupied(uname)) {
            if (!randomize_username(uname)) {
                err = 11;
                return false;
            }
            is_uname_randomized = true;
        }
        struct user_item new_user;
        new_user.unique_email = uemail;
        new_user.unique_name = uname;
        new_user.pass_hash = hashed_pass;
        user_db.insert({uemail, new_user});
        uname_uemail.insert({uname, uemail});
        user_list_fmt += (uname + " (" + uemail + ") " + "\n");
        std::ofstream file_out(db_file_path, std::ios::binary | std::ios::app);
        if (!file_out.is_open()) {
            err = 13;
            return false;
        }
        size_t bytes_to_write = 1 + uemail.size() + 1 + uname.size() + 
                                hashed_pass.size();
        size_t offset = 0;
        std::vector<uint8_t> block(bytes_to_write);
        block[0] = static_cast<uint8_t>(uemail.size() - 1);
        ++ offset;
        std::copy(uemail.begin(), uemail.end(), block.begin() + offset);
        offset += uemail.size();
        block[offset] = static_cast<uint8_t>(uname.size());
        ++ offset;       
        std::copy(uname.begin(), uname.end(), block.begin() + offset);
        offset += uname.size();
        std::copy(hashed_pass.begin(), hashed_pass.end(), block.begin() + offset);
        file_out.write(reinterpret_cast<char *>(block.data()), block.size());
        if (file_out.fail()) {
            err = 13;
            return false;
        }
        return true;
    }

    // type = 0: uemail + password
    // type = 1 (or others): uname + password
    bool user_pass_check (const uint8_t type, const std::string& str, 
        std::string& password, uint8_t& err) {
        
        user_item *ptr_item = nullptr;
        err = 0;
        if (type == 0x00) {
            if (!is_email_registered(str)) {
                err = 2;
                password.clear();
                return false;
            }
            ptr_item = get_user_item_by_uemail(str);
        }
        else {
            if (!is_username_occupied(str)) {
                err = 4;
                password.clear();
                return false;
            }
            ptr_item = get_user_item_by_uname(str);
        }
        if (ptr_item == nullptr) {
            err = 6;
            password.clear();
            return false;
        }
        auto ret = (crypto_pwhash_str_verify(
            (ptr_item->pass_hash).data(), 
            password.c_str(), 
            password.size()) == 0);

        password.clear();
        if (!ret) err = 8;
        return ret;
    }

    std::string& get_user_list () {
        return user_list_fmt;
    }

    std::string get_user_list (bool show_status) {
        if (!show_status)
            return get_user_list();
        std::string list_with_status;
        for (auto& it : user_db) {
            if (it.second.user_status == 1)
                list_with_status += (it.second.unique_name + " (" 
                                    + it.second.unique_email +  ") (in)\n");
            else
                list_with_status += ((it.second.unique_name) + " (" 
                                    + it.second.unique_email + ")\n");
        }
        return list_with_status;
    }

    user_item *get_user_item (const uint8_t type, const std::string& str) {
        if (type == 0x00)
            return get_user_item_by_uemail(str);
        else 
            return get_user_item_by_uname(str);
    }

    // type = 0: uemail
    // type = 1 (or others): uname
    bool bind_user_ctx (const uint8_t type, const std::string& str, 
        const uint64_t& cif) {
        auto ptr_user = get_user_item(type, str);
        if (ptr_user == nullptr)
            return false;
        ptr_user->user_status = 1;
        ptr_user->bind_cif = cif;
        return true;
    }

    bool unbind_user_ctx (const uint8_t type, const std::string& str) {
        user_item *ptr_item = nullptr;
        auto ptr_user = get_user_item(type, str);
        if (ptr_item == nullptr)
            return false;
        ptr_item->user_status = 0;
        ptr_item->bind_cif = 0;
        return true;
    }

    bool get_bind_cif (const uint8_t type, const std::string& str, 
        uint64_t& cif) {
        auto ptr_user = get_user_item(type, str);
        if (ptr_user == nullptr)
            return false;
        if (ptr_user->user_status == 0)
            return false;
        cif = ptr_user->bind_cif;
        return true;
    }

    std::pair<size_t, size_t> get_user_stat () {
        size_t in = 0;
        for (auto& it : user_db) {
            if (it.second.user_status == 1)
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
    std::string key_dir;                            // Key directory
    key_mgr_25519 key_mgr;                          // key manager
    msg_buffer buffer;                              // Message core processor
    user_mgr users;                                 // all users
    session_pool conns;                             // all sessions.
    ctx_pool clients;                               // all clients(contexts).
    int last_error;                                 // error code
    
public:
    // A simple constructor
    lichat_server () {
        server_port = DEFAULT_SERVER_PORT;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(server_port);
        server_fd = -1;
        key_dir = default_key_dir;
        key_mgr = key_mgr_25519(key_dir, "server_");
        buffer = msg_buffer();
        users = user_mgr(default_user_db_path);
        conns = session_pool();
        clients = ctx_pool();
        last_error = 0;
    }

    void set_port (uint16_t port) {
        server_port = port;
        server_addr.sin_port = htons(server_port);
    }

    void set_key_dir (const std::string& dir) {
        key_dir = default_key_dir;
        key_mgr.set_key_dir(dir);
    }

    // Close server and possible FD
    bool close_server (int err) {
        last_error = err;
        if (server_fd != -1) {
            close(server_fd); 
            server_fd = -1;
        }
        return err == 0;
    }

    // Get last error code
    int get_last_error (void) {
        return last_error;
    }

    // Start the server and handle possible failures
    bool start_server (void) {
        if (key_mgr.key_mgr_init() != 0) {
            std::cout << "Key manager not activated." << std::endl;
            return close_server(KEYMGR_FAILED);
        }
        if (users.precheck_user_db() != 0) {
            std::cout << "User database precheck failed. " << users.precheck_user_db() << std::endl;
            return close_server(USERDB_PRECHECK_FAILED);
        }
        server_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (server_fd == -1)
            return close_server(SOCK_FD_INVALID);
        if (bind(server_fd, (sockaddr *)&server_addr, (socklen_t)sizeof(server_addr)))
            return close_server(SOCK_BIND_FAILED);
        std::cout << "LightChat (LiChat) Service started." << std::endl 
                  << "UDP Listening Port: " << server_port << std::endl;
        return true;
    }

    bool is_session_valid (const uint64_t& cinfo_hash) {
        return (conns.get_session(cinfo_hash) != nullptr);
    }

    // Simplify the socket send function.
    int simple_send (const uint64_t& cinfo_hash, const uint8_t *msg, size_t n) {
        auto p_conn = conns.get_session(cinfo_hash);
        if (p_conn == nullptr)
            return -3; // Invalid cinfo_hash
        auto addr = p_conn->get_src_addr();
        return sendto(server_fd, msg, n, MSG_CONFIRM, (struct sockaddr *)&addr, 
                        sizeof(addr));
    }

    // Simplify the socket send function.
    int simple_send (const struct sockaddr_in& addr, const uint8_t *msg, 
        size_t n) {

        return sendto(server_fd, msg, n, MSG_CONFIRM, 
                        (struct sockaddr *)&addr, sizeof(addr));
    }

    // Simplify the socket send function.
    int simple_send (uint8_t header, const struct sockaddr_in& addr, 
        const uint8_t *msg, size_t n) {

        if (n + 1 > buffer.send_buffer.size()) {
            return -3;
        }
        buffer.send_buffer[0] = header;
        std::copy(msg, msg + n, buffer.send_buffer.begin() + 1);
        buffer.send_bytes = n + 1;
        return sendto(server_fd, buffer.send_buffer.data(), buffer.send_bytes, 
                        MSG_CONFIRM, (struct sockaddr *)&addr, sizeof(addr));
    }

    // Simplify the socket send function.
    // Format : 1-byte header + 
    //          if 0x00 header, add a 32byte pubkey, otherwise skip + 
    //          aes_nonce + 
    //          aes_gcm_encrypted (sid + cinfo_hash + msg_body)
    int simple_secure_send (const uint8_t header, const uint64_t cif, 
        const uint8_t *raw_msg, size_t raw_n) {

        std::array<uint8_t, crypto_aead_aes256gcm_NPUBBYTES> server_aes_nonce;
        size_t offset = 0, aes_encrypted_len = 0;
        auto conn = conns.get_session(cif);
        if (conn == nullptr)
            return -1;
        auto cif_bytes = lc_utils::u64_to_bytes(cif);
        auto sid = conn->get_server_sid();
        auto aes_key = conn->get_aes_gcm_key();
        auto addr = conn->get_src_addr();
        // Padding the first byte
        buffer.send_buffer[0] = header;
        ++ offset;
        
        if (header == 0x00) {
            // server_sign_key + signed(server_publick_key)
            std::array<uint8_t, crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES> 
                signed_server_cpk;

            if (!lc_utils::sign_crypto_pk(key_mgr, signed_server_cpk)) {
                buffer.send_bytes = offset;
                return 1;
            }
            auto server_sign_pk = key_mgr.get_sign_pk();
            std::copy(server_sign_pk.begin(), server_sign_pk.end(), 
                        buffer.send_buffer.begin() + offset);
            offset += server_sign_pk.size();
            std::copy(signed_server_cpk.begin(), signed_server_cpk.end(), 
                        buffer.send_buffer.begin() + offset);
            offset += signed_server_cpk.size();
        }
        else if (header == 0x01) { // Verify the signature.
            unsigned long long signed_len = 0;
            auto sign_sk = key_mgr.get_sign_sk();
            std::array<uint8_t, crypto_sign_BYTES + sizeof(ok)> signed_ok;
            if (crypto_sign(signed_ok.data(), &signed_len, ok, sizeof(ok), 
                sign_sk.data()) != 0) {

                buffer.send_bytes = offset;
                return 1;
            }
            std::copy(signed_ok.begin(), signed_ok.end(), 
                        buffer.send_buffer.begin() + offset);
            offset += signed_ok.size();
        }
    
        // Padding the aes_nonce
        lc_utils::generate_aes_nonce(server_aes_nonce);
        std::copy(server_aes_nonce.begin(), server_aes_nonce.end(), 
                    buffer.send_buffer.begin() + offset);
        offset += server_aes_nonce.size();
        if ((offset + sid.size() + cif_bytes.size() + raw_n + 
            crypto_aead_aes256gcm_ABYTES) > BUFF_BYTES) {

            buffer.send_bytes = offset;
            return 3; // buffer overflow occur.
        }
        // Construct the raw message: sid + cif + msg_body
        std::copy(sid.begin(), sid.end(), buffer.send_aes_buffer.begin());
        std::copy(cif_bytes.begin(), cif_bytes.end(), 
                    buffer.send_aes_buffer.begin() + sid.size());
        std::copy(raw_msg, raw_msg + raw_n, buffer.send_aes_buffer.begin() + 
                    sid.size() + cif_bytes.size());
        // Record the buffer occupied size.
        buffer.send_aes_bytes = sid.size() + cif_bytes.size() + raw_n;

        // AES encrypt and padding to the send_buffer.
        auto res = crypto_aead_aes256gcm_encrypt(
            buffer.send_buffer.data() + offset, 
            reinterpret_cast<unsigned long long *>(&aes_encrypted_len),
            reinterpret_cast<const uint8_t *>(buffer.send_aes_buffer.data()),
            buffer.send_aes_bytes, 
            NULL, 0, NULL, 
            server_aes_nonce.data(), aes_key.data()
        );
        buffer.send_bytes = offset + aes_encrypted_len;
        if (res != 0) 
            return 5;
        auto ret = simple_send(addr, buffer.send_buffer.data(), buffer.send_bytes);
        if (ret < 0) 
            return 7;
        return ret;
    }

    int notify_reset_conn (uint64_t& cinfo_hash, const uint8_t *msg, 
        size_t size_of_msg, bool clean_client) {

        auto ret1 = simple_send(cinfo_hash, msg, size_of_msg);
        auto ret2 = simple_send(cinfo_hash, reinterpret_cast<const uint8_t *>
                                (connection_reset), sizeof(connection_reset));
        int ret3 = 1;
        if (clean_client) {
            clients.get_ctx(cinfo_hash)->clear_ctx();
        } 
        else {
            ret3 = simple_send(cinfo_hash, reinterpret_cast<const uint8_t *>
                                (main_menu), sizeof(main_menu));
            clients.get_ctx(cinfo_hash)->reset_ctx();
        }
        if ((ret1 >= 0) && (ret2 >= 0) && (ret3 >= 0))
            return 0;
        return 1;
    }

    // Convert an addr to a message
    static std::string addr_to_msg (const struct sockaddr_in addr) {
        std::ostringstream oss;
        char ip_cstr[INET_ADDRSTRLEN];
        std::strncpy(ip_cstr, inet_ntoa(addr.sin_addr), INET_ADDRSTRLEN);
        oss << ip_cstr << ":" << ntohs(addr.sin_port) << std::endl;
        return oss.str();
    }

    bool get_cinfo_by_uid (uint64_t& ret, const std::string& user_uid) {
        auto map = clients.get_ctx_map();
        for (auto it : map) {
            if (it.second.get_bind_uid() == user_uid) {
                ret = it.first; 
                return true;
            }
        }
        return false;
    }

    bool is_user_signed_in (const std::string& user_uid) {
        auto map = clients.get_ctx_map();
        uint64_t tmp;
        return get_cinfo_by_uid(tmp, user_uid);
    }

    size_t broadcasting (const uint8_t *msg, const size_t msg_bytes) {
        if (1 + crypto_sign_BYTES + msg_bytes > BUFF_BYTES)
            return 0;
        size_t offset = 0;
        buffer.send_buffer[0] = 0x11;   // Unencrypted message.
        ++ offset;
        auto server_ssk = key_mgr.get_sign_sk();
        unsigned long long signed_len = 0;
        if (crypto_sign(buffer.send_buffer.data() + 1, &signed_len, msg, msg_bytes, 
            server_ssk.data()) != 0)
            return 0;
        buffer.send_bytes = 1 + signed_len;
        size_t sent_out = 0;
        for (auto elem : clients.get_ctx_map()) {
            if (elem.second.get_status() != 2)
                continue;
            auto cif = elem.first;
            session_item *ptr_session = conns.get_session(cif);
            auto cif_bytes = lc_utils::u64_to_bytes(cif);
            if (ptr_session == nullptr)
                continue;
            auto addr = ptr_session->get_src_addr();
            if (simple_send(addr, buffer.send_buffer.data(), 
                buffer.send_bytes) >= 0)
                ++ sent_out;
        }
        return sent_out;
    }
    
    // Broadcasting to all connected clients (include or exclude current/self).
    size_t secure_broadcasting (const uint8_t *msg, const size_t msg_bytes) {
        if (lc_utils::calc_encrypted_len(msg_bytes) > BUFF_BYTES)
            return 0;
        size_t sent_out = 0;
        for (auto elem : clients.get_ctx_map()) {
            if (elem.second.get_status() != 2)
                continue;
            auto cif = elem.first;
            session_item *ptr_session = conns.get_session(cif);
            if (ptr_session == nullptr)
                continue;
            if (simple_secure_send(0x10, cif, msg, msg_bytes) >= 0)
                ++ sent_out;
        }
        return sent_out;
    }

    bool decrypt_recv_0x10raw_bytes (const size_t recved_raw_bytes, 
        uint64_t& ret_cif) {

        if (recved_raw_bytes < lc_utils::calc_encrypted_len(1))
            return false;
        size_t offset = 0; // Omit first byte 0x10.
        auto header = buffer.recv_raw_buffer[0];
        if (header != 0x10) 
            return false;
        ++ offset;
        std::array<uint8_t, CIF_BYTES> cif_bytes;
        std::array<uint8_t, crypto_aead_aes256gcm_NPUBBYTES> aes_nonce;
        auto beg = buffer.recv_raw_buffer.begin();
        unsigned long long aes_decrypted_len = 0;
        std::copy(beg + offset, beg + offset + CIF_BYTES, cif_bytes.begin());
        offset += CIF_BYTES;
        std::copy(beg + offset, beg + offset + crypto_aead_aes256gcm_NPUBBYTES, 
                    aes_nonce.begin());
        offset += crypto_aead_aes256gcm_NPUBBYTES;

        auto cinfo_hash = lc_utils::bytes_to_u64(cif_bytes);
        auto ptr_session = conns.get_session(cinfo_hash);
        if (ptr_session == nullptr)
            return false;
        if (ptr_session->get_status() != 2)
            return false;
        auto aes_key = ptr_session->get_aes_gcm_key();
        auto sid = ptr_session->get_server_sid();
        auto ret = 
            (crypto_aead_aes256gcm_decrypt(
                buffer.recv_aes_buffer.begin(), &aes_decrypted_len, NULL,
                beg + offset, recved_raw_bytes - offset,
                NULL, 0,
                aes_nonce.data(), aes_key.data()
            ) == 0);
        buffer.recv_aes_bytes = aes_decrypted_len;
        if (aes_decrypted_len <= SID_BYTES)
            return false;
        if (ret) {
            if (std::memcmp(buffer.recv_aes_buffer.begin(), sid.begin(), 
                sid.size())==0) {

                ret_cif = cinfo_hash;
                return true;
            }
            return false;
        }
        return false;
    }

    std::string user_list_to_msg () {
        std::string user_list_fmt = users.get_user_list(true);
        std::ostringstream oss;
        std::pair<size_t, size_t> stat_par = users.get_user_stat();
        oss << "[SYSTEM_INFO] currently " << stat_par.first << " signed up users, " 
            << stat_par.second << " signed in users. list:\n"
            << "* (in) currently signed in.\n" << user_list_fmt << "\n\n"; 
        return oss.str();
    }

    bool is_valid_clnt_err_msg (const uint8_t *clnt_err_code, 
        uint64_t& cinfo_hash) {

        size_t expected_bytes = 1 + ERR_CODE_BYTES + 
                                crypto_sign_PUBLICKEYBYTES + crypto_sign_BYTES + 
                                CID_BYTES + crypto_box_PUBLICKEYBYTES;
        if (buffer.recv_raw_bytes != expected_bytes)
            return false;
        size_t offset = 0;
        auto beg = buffer.recv_raw_buffer.begin();
        ++ offset;
        if (std::memcmp(beg + offset, clnt_err_code, ERR_CODE_BYTES) != 0)
            return false; // Garbage message, ommit.
        offset += ERR_CODE_BYTES;
        unsigned long long unsign_len = 0;
        std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> client_sign_pk;
        std::copy(beg + offset, beg + offset + crypto_sign_PUBLICKEYBYTES, 
                    client_sign_pk.begin());
        offset += crypto_sign_PUBLICKEYBYTES;
        if (crypto_sign_open(nullptr, &unsign_len, beg + offset, 
            crypto_sign_BYTES + CID_BYTES + crypto_box_PUBLICKEYBYTES, 
            client_sign_pk.data()) != 0)
            return false; // Unsigned message. ommit.

        offset += crypto_sign_BYTES;
        std::array<uint8_t, CID_BYTES> cid;
        std::array<uint8_t, crypto_box_PUBLICKEYBYTES> cpk;
        std::copy(beg + offset, beg + offset + CID_BYTES, cid.begin());
        offset += CID_BYTES;
        std::copy(beg + offset, beg + offset + crypto_box_PUBLICKEYBYTES, 
                    cpk.begin());
        uint64_t hash = lc_utils::hash_client_info(cid, cpk);
        if (is_session_valid(hash)) {
            cinfo_hash = hash;
            return true;
        }
        return false;
    }

    // Check all the connections and delete any inactive connections and their
    // contexts. Update the user status.
    size_t check_all_conns (time_t now) {
        auto& map = conns.get_session_map();
        size_t erased = 0;
        uint64_t cif_curr = 0;
        for (auto it = map.begin(); it != map.end(); ) {
            if (it->second.is_inactive(now)) {
                auto cif = it->first;
                auto p_ctx = clients.get_ctx(cif);
                if (p_ctx) {
                    auto uid = p_ctx->get_bind_uid();
                    if (users.get_bind_cif(0, uid, cif_curr) && cif_curr == cif)
                        users.unbind_user_ctx(0, uid);
                    clients.delete_ctx(cif);
                }
                auto status = it->second.get_status();
                it = map.erase(it);
                ++ erased;
                conns.update_stats_at_session_delete(status);
            }
            else {
                ++ it;
            }
        }
        return erased;
    }

    // Main processing method.
    bool run_server (void) {
        if (!key_mgr.is_activated()) {
            std::cout << "Key manager not activated." << std::endl;
            return close_server(KEYMGR_FAILED);
        }
        if (server_fd == -1) {
            std::cout << "Server not started." << std::endl;
            return close_server(SOCK_FD_INVALID);
        }
        size_t user_preloaded = 0;
        users.preload_user_db(user_preloaded);
        std::cout << "Preloaded " << user_preloaded << " users." << std::endl;
        struct timeval tv;
        tv.tv_sec = SERVER_RECV_WAIT_SECS;
        tv.tv_usec = 0;
        if (setsockopt(server_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, 
            sizeof(tv)) < 0) {
            return close_server(SET_TIMEOUT_FAILED);
        }
        std::array<uint8_t, crypto_aead_aes256gcm_NPUBBYTES> client_aes_nonce;
        size_t aes_enc_len = 0;
        size_t aes_dec_len = 0;
        std::string timestamp;
        time_t check_t = lc_utils::now_time();
        while (true) {
            // Server checks all connections
            auto now = lc_utils::now_time();
            if (now - check_t >= SERVER_CONNS_CHECK_SECS) {
                std::cout << "Checking all connections ..." << std::endl;
                auto erased = check_all_conns(now);
                check_t = now;
                std::cout << "Erased " << erased << " inactive." << std::endl;
            }
            struct sockaddr_in client_addr;
            auto addr_len = sizeof(client_addr);
            unsigned long long unsign_len = 0, sign_len = 0;
            buffer.clear_buffer();
            auto bytes_recv = recvfrom(server_fd, buffer.recv_raw_buffer.data(), 
                                       buffer.recv_raw_buffer.size(), 0, 
                                       (struct sockaddr *)&client_addr, 
                                       (socklen_t *)&addr_len);
            if (bytes_recv < 0)
                continue;

            buffer.recv_raw_bytes = bytes_recv;
            if (buffer.recved_insuff_bytes(SERVER_RECV_MIN_BYTES) || 
                buffer.recved_overflow()) {

                std::cout << "Received message size invalid." << std::endl;
                continue; // If size is invalid, ommit.
            }       
            std::cout << lc_utils::now_time_to_str() << std::endl
                      << ">> Received from: " << std::endl 
                      << inet_ntoa(client_addr.sin_addr)
                      << ':' << ntohs(client_addr.sin_port) << '\t';
            std::cout << std::endl << std::hex << std::setw(2) 
                      << std::setfill('0');
            for (size_t i = 0; i < 10; ++ i) 
                std::cout << (int)buffer.recv_raw_buffer[i] << ' ';
            if (bytes_recv > 10) 
                std::cout << "... ";
            std::cout << std::dec << bytes_recv << " bytes." << std::endl;

            
            auto beg = buffer.recv_raw_buffer.begin();
            size_t offset = 0;
            auto header = buffer.recv_raw_buffer[0];
            ++ offset;
            if (header == 0x00 || header == 0x01) {
                size_t expected_size = 1 + crypto_sign_PUBLICKEYBYTES + 
                                        crypto_sign_BYTES + CID_BYTES + 
                                        crypto_box_PUBLICKEYBYTES;

                if (buffer.recv_raw_bytes != expected_size) {
                    simple_send(client_addr, server_ff_failed, 
                                sizeof(server_ff_failed));
                    continue;
                }

                // 0x00/0x01 + client_sign_key + signed (CID + client_pub_key);
                std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> spk;
                std::copy(beg + offset, 
                        beg + offset + crypto_sign_PUBLICKEYBYTES, spk.begin());
                offset += crypto_sign_PUBLICKEYBYTES;

                if (crypto_sign_open(nullptr, &unsign_len, beg + offset, 
                    buffer.recv_raw_bytes - offset, spk.data()) != 0) {

                    simple_send(client_addr, server_ff_failed, 
                                sizeof(server_ff_failed));
                    continue;
                }
                offset += crypto_sign_BYTES;
                std::array<uint8_t, CID_BYTES> cid;
                std::array<uint8_t, crypto_box_PUBLICKEYBYTES> cpk;
                std::copy(beg + offset, beg + offset + CID_BYTES, cid.begin());
                offset += CID_BYTES;
                std::copy(beg + offset, beg + offset + crypto_box_PUBLICKEYBYTES, 
                            cpk.begin());

                offset += crypto_box_PUBLICKEYBYTES;
                uint64_t cinfo_hash = lc_utils::hash_client_info(cid, cpk);
                if (conns.get_session(cinfo_hash) != nullptr)
                    continue; // If the session has been established, ommit.
                conns.prepare_add_session(cid, cpk, spk, key_mgr);
                auto this_conn = conns.get_session(cinfo_hash);
                if (this_conn == nullptr) {
                    simple_send(client_addr, 
                                reinterpret_cast<const uint8_t *>(fatal_error), 
                                sizeof(fatal_error));
                    return close_server(INTERNAL_FATAL);
                }
                this_conn->set_src_addr(client_addr);
                if (header == 0x00)
                    simple_secure_send(0x00, cinfo_hash, ok, sizeof(ok));
                else
                    simple_secure_send(0x01, cinfo_hash, ok, sizeof(ok));
                continue;
            }
            if (header == 0xFF || header == 0xEF || header == 0xDF) {
                uint64_t cinfo_hash;
                if (header == 0xFF) {
                    if (!is_valid_clnt_err_msg(client_ff_timout, cinfo_hash))
                    continue;
                }
                else if (header == 0xEF) {
                    if (!is_valid_clnt_err_msg(client_ef_keyerr, cinfo_hash))
                    continue;
                }
                else {
                    if (!is_valid_clnt_err_msg(client_df_msgerr, cinfo_hash))
                    continue;
                }
                if (conns.get_session(cinfo_hash)->get_status() != 1)
                    continue;
                conns.delete_session(cinfo_hash);
                continue;
            }
            if (header == 0x02) {
                size_t expected_size = 1 + CIF_BYTES + 
                                    crypto_aead_aes256gcm_NPUBBYTES + SID_BYTES 
                                    + sizeof(ok) + crypto_aead_aes256gcm_ABYTES;
                
                if (buffer.recv_raw_bytes != expected_size)
                    continue;

                auto pos = buffer.recv_raw_buffer.begin() + 1;
                std::array<uint8_t, CIF_BYTES> cinfo_hash_bytes;
                std::copy(pos, pos + CIF_BYTES, cinfo_hash_bytes.begin());
                std::copy(pos + CIF_BYTES, 
                            pos + CIF_BYTES + crypto_aead_aes256gcm_NPUBBYTES, 
                            client_aes_nonce.begin());
                
                auto cinfo_hash = lc_utils::bytes_to_u64(cinfo_hash_bytes);
                auto this_conn = conns.get_session(cinfo_hash);
                if (this_conn == nullptr)
                    continue; // If this is not a established session, omit.
                if (this_conn->get_status() != 1)
                    continue; // If it is not a prepared session, omit.
                auto aes_key = this_conn->get_aes_gcm_key();
                auto server_sid = this_conn->get_server_sid();
                aes_dec_len = 0;
                auto is_aes_ok = 
                    ((crypto_aead_aes256gcm_decrypt(
                        buffer.recv_aes_buffer.begin(), 
                        reinterpret_cast<unsigned long long *>(&aes_dec_len),
                        NULL,
                        pos + CIF_BYTES + crypto_aead_aes256gcm_NPUBBYTES, 
                        SID_BYTES + sizeof(ok) + crypto_aead_aes256gcm_ABYTES,
                        NULL, 0,
                        client_aes_nonce.data(), aes_key.data()
                    ) == 0) && (aes_dec_len == SID_BYTES + sizeof(ok)));

                buffer.recv_aes_bytes = aes_dec_len;
                auto is_msg_ok = 
                    ((std::memcmp(buffer.recv_aes_buffer.data(), 
                                server_sid.data(), SID_BYTES) == 0 &&
                    std::memcmp(buffer.recv_aes_buffer.data() + SID_BYTES, 
                                ok, sizeof(ok)) == 0));
                
                if (is_aes_ok && is_msg_ok) {
                    this_conn->activate(); // Activate the session
                    this_conn->set_src_addr(client_addr); // Update the addr.
                    simple_secure_send(0x02, cinfo_hash, ok, sizeof(ok));
                    continue;
                }
                offset = 0;
                auto beg = buffer.send_buffer.begin();
                // 1 + 6-byte err + CIF + deleted_sid + server_sign_pk + signed(server_cpk)
                if (!is_aes_ok) 
                    std::copy(std::begin(server_ef_keyerr), 
                                std::end(server_ef_keyerr), beg + offset);
                else
                    std::copy(std::begin(server_df_msgerr), 
                                std::end(server_df_msgerr), beg + offset);
                offset += 1 + ERR_CODE_BYTES;

                // Copy cinfo_hash
                std::copy(cinfo_hash_bytes.begin(), cinfo_hash_bytes.end(),  
                            beg + offset);
                offset += cinfo_hash_bytes.size();

                // Copy server_sid
                std::copy(server_sid.begin(), server_sid.end(), beg + offset);
                offset += server_sid.size();

                // Copy server_sign_pk
                auto server_spk = key_mgr.get_sign_pk();
                std::copy(server_spk.begin(), server_spk.end(), beg + offset);
                offset += server_spk.size();

                // Sign the server_crypto_pk and copy
                std::array<uint8_t, crypto_sign_BYTES + 
                            crypto_box_PUBLICKEYBYTES> signed_server_cpk;

                lc_utils::sign_crypto_pk(key_mgr, signed_server_cpk);
                std::copy(signed_server_cpk.begin(), signed_server_cpk.end(), 
                            beg + offset);
                
                // Calc the total bytes.
                buffer.send_bytes = offset + signed_server_cpk.size();

                // Send out the message.
                simple_send(client_addr, buffer.send_buffer.data(), 
                            buffer.send_bytes);

                // Delete the session because sid has been exposed.
                conns.delete_session(cinfo_hash); 
                continue;
            }
            // 1. Heartbeat message, needs to beat back.
            //    0x1F + signed(CIF)
            // 2. Goodbye message, delete the connection and context.
            //    0x1F + signed(CIF + '!')
            if (header == 0x1F) {
                if (buffer.recv_raw_bytes != HEARTBEAT_BYTES &&
                    buffer.recv_raw_bytes != GOODBYE_BYTES)
                    continue;
                std::array<uint8_t, CIF_BYTES> recved_cif_bytes;
                auto beg = buffer.recv_raw_buffer.begin();
                auto cif_pos = beg + 1 + crypto_sign_BYTES;
                std::copy(cif_pos, cif_pos + CIF_BYTES, 
                          recved_cif_bytes.begin());
                auto recved_cif = lc_utils::bytes_to_u64(recved_cif_bytes);
                auto ptr_session = conns.get_session(recved_cif);
                if (ptr_session == nullptr)
                    continue; // Not a valid cif.
                auto client_spk = ptr_session->get_client_sign_key();
                if (crypto_sign_open(nullptr, &unsign_len, beg + 1,
                    buffer.recv_raw_bytes - 1, client_spk.data()))
                    continue;  // Not a valid signature.

                if (buffer.recv_raw_bytes == HEARTBEAT_BYTES) {
                    // All the checks done, update the addr.
                    ptr_session->set_src_addr(client_addr);
                    ptr_session->set_last_heartbeat(lc_utils::now_time());
                    std::array<uint8_t, HEARTBEAT_BYTES> packet;
                    packet[0] = 0x1F;
                    if (crypto_sign(packet.data() + 1, &sign_len, 
                        recved_cif_bytes.data(), recved_cif_bytes.size(), 
                        key_mgr.get_sign_sk().data()) != 0) 
                        return close_server(MSG_SIGNING_FAILED);
                    simple_send(client_addr, packet.data(), packet.size());
                    continue;
                }
                auto last_byte = buffer.recv_raw_buffer[buffer.recv_raw_bytes - 1];
                // Now if the last byte is '!', it is a goodbye packet.
                if (last_byte != '!')
                    continue; // Not a valid packet.

                auto uemail = clients.get_ctx(recved_cif)->get_bind_uid();
                auto uname = users.get_uname_by_uemail(uemail);
                // Delete all the context info.
                clients.delete_ctx(recved_cif);
                // Delete all the session data.
                conns.delete_session(recved_cif);

                // User signed off.
                users.unbind_user_ctx(0, uemail);
                
                timestamp = lc_utils::now_time_to_str();
                std::string bcast_msg = 
                    timestamp + ",[SYSTEM_BCAST]," + (*uname) + " signed out!";
                //std::cout << bcast_msg << std::endl;
                // Broadcasting to all active users.      
                broadcasting(
                    reinterpret_cast<const uint8_t *>(bcast_msg.c_str()), 
                    bcast_msg.size());
                continue;
            }
            if (header == 0x10) {
                size_t expected_min_size = 1 + CIF_BYTES + 
                        crypto_aead_aes256gcm_NPUBBYTES + SID_BYTES + 
                        crypto_aead_aes256gcm_ABYTES;

                if (buffer.recv_raw_bytes <= expected_min_size)
                    continue; // Empty or invalid message. Omit.
                uint64_t cinfo_hash;
                if (!decrypt_recv_0x10raw_bytes(buffer.recv_raw_bytes, 
                    cinfo_hash)) {
                    continue;
                }   
                auto msg_body = buffer.recv_aes_buffer.data() + SID_BYTES;
                auto msg_size = buffer.recv_aes_bytes - SID_BYTES;
                conns.get_session(cinfo_hash)->set_src_addr(client_addr); // Update the client addr.
                if (!clients.is_valid_ctx(cinfo_hash)) 
                    clients.add_ctx(cinfo_hash);
                auto this_client = clients.get_ctx(cinfo_hash);
                if (this_client == nullptr)
                    continue; // Abnormal.
                auto stat = this_client->get_status();
                if (stat == 0) {
                    this_client->set_status(1);
                    stat = this_client->get_status(); // Retrive the latest status.
                }
                if (stat == 1) {
                    size_t min_size = 1 + 1 + ULOGIN_MIN_BYTES + 1 + 
                                        PASSWORD_MIN_BYTES + 1;
                    size_t max_size = 1 + 1 + UEMAIL_MAX_BYTES + 1 + 
                                        UNAME_MAX_BYTES + 1 +
                                        PASSWORD_MAX_BYTES + 1;

                    if (msg_size < min_size || msg_size > max_size || 
                        msg_body[0] > 0x01)
                        continue; // option + type + user_name &/user_email + '0x00' + password + 0x00

                    auto option = msg_body[0];
                    if (option == 0x00) { // Signing up.
                        if (msg_size < 1 + 1 + ULOGIN_MIN_BYTES + 1 + 
                            ULOGIN_MIN_BYTES + 1 + PASSWORD_MIN_BYTES + 1)
                            continue; // Invalid length.

                        auto reg_info = lc_utils::split_buffer(
                            msg_body + 2, msg_size - 2, 0x00, 3);

                        if (reg_info.size() < 3) 
                            continue; // Invalid format.
                        uint8_t err = 0;
                        bool is_uname_randomized = false;
                        if (!users.add_user(reg_info[0], reg_info[1], 
                            reg_info[2], err, is_uname_randomized)) {
                            simple_secure_send(0x10, cinfo_hash, &err, 1);
                            continue;
                        }
                        std::string uinfo_res;
                        if (is_uname_randomized) 
                            uinfo_res = "!" + reg_info[0] + "!" + reg_info [1];
                        else
                            uinfo_res = ":" + reg_info[0] + ":" + reg_info [1];
                        
                        simple_secure_send(0x10, cinfo_hash, 
                            reinterpret_cast<const uint8_t *>(uinfo_res.c_str()), 
                            uinfo_res.size());

                        this_client->set_bind_uid(reg_info[0]);
                        this_client->set_status(2);
                        users.bind_user_ctx(0, reg_info[0], cinfo_hash);
                        timestamp = lc_utils::now_time_to_str();
                        std::string bcast_msg = 
                            timestamp + ",[SYSTEM_BCAST]," + reg_info[1] + 
                            " signed up and signed in!";
                        broadcasting(
                            reinterpret_cast<const uint8_t *>(bcast_msg.c_str()), 
                            bcast_msg.size());
                        continue;
                    }
                    // Processing sign in process. signin_type = 0: uemail, signin_type = 1: uname;
                    auto signin_type = msg_body[1];
                    if (signin_type != 0x00 && signin_type != 0x01) 
                        continue;
                    auto signin_info = lc_utils::split_buffer(
                                        msg_body + 2, msg_size - 2, 0x00, 2);
                    
                    if (signin_info.size() < 2)
                        continue;
                    uint8_t err = 0;
                    // signin_info[0]: uemail or uname, signin_info[1]: password
                    if (!users.user_pass_check(signin_type, signin_info[0], 
                        signin_info[1], err)) {

                        simple_secure_send(0x10, cinfo_hash, &err, 1);
                        continue;
                    }
                    std::string uname, uemail;
                    if (signin_type == 0x00) {
                        uemail = signin_info[0];
                        uname = *(users.get_uname_by_uemail(signin_info[0]));
                    }
                    else {
                        uemail = *(users.get_uemail_by_uname(signin_info[0]));
                        uname = signin_info[0];
                    }
                    std::string uinfo_res =
                        ":" + uemail + ":" + uname;
                    simple_secure_send(0x10, cinfo_hash, 
                        reinterpret_cast<const uint8_t *>(uinfo_res.c_str()), 
                        uinfo_res.size());
                                
                    this_client->set_bind_uid(uemail);
                    this_client->set_status(2);
                    uint64_t prev_cif = 0;
                    if (users.get_bind_cif(0, uemail, prev_cif)) {
                        timestamp = lc_utils::now_time_to_str();
                        simple_secure_send(0x10, prev_cif, 
                            reinterpret_cast<const uint8_t *>(s_signout), 
                            sizeof(s_signout));
                        clients.delete_ctx(prev_cif);
                        conns.delete_session(prev_cif);
                    }
                    users.bind_user_ctx(0, uemail, cinfo_hash);
                    timestamp = lc_utils::now_time_to_str();
                    std::string bcast_msg = timestamp + ",[SYSTEM_BCAST]," + 
                                            uname + " signed in!";
                    broadcasting(
                        reinterpret_cast<const uint8_t *>(bcast_msg.c_str()), 
                        bcast_msg.size());
                    continue;
                }
                // stat = 2
                auto sender_uemail = this_client->get_bind_uid();
                auto sender_uname = users.get_uname_by_uemail(sender_uemail);

                std::string timestamp = lc_utils::now_time_to_str();
                auto response_size = timestamp.size() + 1 + 
                                    sender_uname->size() + 1 + msg_size;

                std::vector<uint8_t> resp(response_size, ',');
                offset = 0;
                std::copy(timestamp.begin(), timestamp.end(), resp.begin());
                offset += timestamp.size() + 1;
                std::copy(sender_uname->begin(), sender_uname->end(), 
                          resp.begin() + offset);
                offset += sender_uname->size() + 1;
                std::copy(msg_body, msg_body + msg_size, resp.begin() + offset);
                //std::cout << std::endl 
                //          << std::string((char *)resp.data(), resp.size()) 
                //          << std::endl << std::endl;
                secure_broadcasting(resp.data(), resp.size());
            }
        }
    }
};

// The simplest driver. You can improve it if you'd like to go further.
int main (int argc, char **argv) {
    lichat_server new_server;
    if (sodium_init() < 0) {
        std::cout << "Failed to init libsodium." << std::endl;
        return 1;
    }
    uint16_t port = DEFAULT_SERVER_PORT;
    if (argc > 1) {
        if (lc_utils::string_to_u16(argv[1], port))
            std::cout << "Using the specified port: " << port << std::endl;
        else
            std::cout << "Specified port " << argv[1] 
                      << " is invalid. Using the default 8081." << std::endl;
    }
    else {
        std::cout << "No port specified, using the default 8081." << std::endl;
    }
    new_server.set_port(port);
    if (!new_server.start_server()) {
        std::cout << "Failed to start server. Error Code: " 
                  << new_server.get_last_error() << std::endl;
        return 3;
    }
    return new_server.run_server();
}
