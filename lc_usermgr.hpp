#pragma once

#include <sstream>
#include <string>
#include <unordered_map>

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
    std::string                                  user_list_fmt;

public:
    user_mgr() {}

    user_mgr(const std::string& path) : db_file_path(path) {}

    // Return 0: db_file_path is good to read/write
    // Return 1 or 3: db_file_path is not good to read/write
    int precheck_user_db()
    {
        if (db_file_path.empty())
            db_file_path = default_user_db_path;
        std::ifstream file_in(db_file_path, std::ios::in | std::ios::binary);
        if (!file_in.is_open()) {
            // Create a file.
            std::ofstream file_out(db_file_path, std::ios::binary);
            if (!file_out.is_open())
                return 1; // Failed to create a db file.
            // Write the headers into it.
            file_out.write(user_db_header.data(), user_db_header.size());
            file_out.close();
            return 0;
        }
        // If the file is good to open, check the format.
        std::vector<char> vec(user_db_header.size());
        file_in.read(vec.data(), user_db_header.size());
        std::streamsize bytes_read = file_in.gcount();
        if (bytes_read != user_db_header.size())
            return 3;
        std::string header_str(vec.begin(), vec.begin() + vec.size());
        if (header_str != user_db_header)
            return 5; // The header is incorrect.
        file_in.close();
        return 0; // The file is good to go.
    }

    int preload_user_db(size_t& loaded)
    {
        if (user_db.size() > 0)
            return 1; // This operation is only valid at the beginning of the
                      // running.

        if (precheck_user_db() != 0)
            return 3; // Failed to precheck the db file.

        std::ifstream file_in(db_file_path, std::ios::in | std::ios::binary);
        if (!file_in.is_open())
            return 5; // File I/O Error.
        std::streampos skip = user_db_header.size();
        file_in.seekg(skip, std::ios::beg);
        if (!file_in)
            return 7; // Not a valid file format.
        bool   fread_error = false;
        size_t load_items  = 0;
        while (true) {
            uint8_t                                  uemail_bytes;
            uint8_t                                  uname_bytes;
            std::array<char, crypto_pwhash_STRBYTES> passhash_read;
            file_in.read(reinterpret_cast<char*>(&uemail_bytes), 1);
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
            size_t            uemail_read_bytes = static_cast<size_t>(uemail_bytes) + 1;
            std::vector<char> uemail_read(uemail_read_bytes);
            file_in.read(uemail_read.data(), uemail_read.size());
            if (file_in.gcount() != uemail_read_bytes) {
                fread_error = true;
                break;
            }
            // Uname length is the read bytes, no offset.
            file_in.read(reinterpret_cast<char*>(&uname_bytes), 1);
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
            std::string uemail_str(uemail_read.begin(), uemail_read.begin() + uemail_read.size());
            std::string uname_str(uname_read.begin(), uname_read.begin() + uname_read.size());
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
            new_user.unique_name  = uname_str;
            new_user.pass_hash    = passhash_read;
            user_db.insert({uemail_str, new_user});
            uname_uemail.insert({uname_str, uemail_str});
            ++load_items;
        }
        file_in.close();
        loaded = load_items;
        if (fread_error)
            return 9;
        return 0;
    }

    bool is_email_registered(const std::string& email)
    {
        return (user_db.find(email) != user_db.end());
    }

    static std::string email_to_uid(const std::string& valid_email)
    {
        uint8_t sha256_hash[crypto_hash_sha256_BYTES];
        crypto_hash_sha256(sha256_hash, reinterpret_cast<const unsigned char*>(valid_email.c_str()), valid_email.size());

        char b64_cstr[crypto_hash_sha256_BYTES * 2];
        sodium_bin2base64(b64_cstr, crypto_hash_sha256_BYTES * 2, sha256_hash, crypto_hash_sha256_BYTES, sodium_base64_VARIANT_ORIGINAL);

        return std::string(b64_cstr);
    }

    // If the provided username is duplicated, try randomize it with a suffix
    // The suffix comes from a random 6-byte block (2 ^ 48 possibilities)
    // If the username is still duplicate after randomization, return false
    // else return true.
    bool randomize_username(std::string& uname)
    {
        uint8_t random_suffix3[3], random_suffix6[6], random_suffix9[9];
        auto    check = [](std::string& str, uint8_t* bytes, size_t n) {
            size_t b64_size = sodium_base64_encoded_len(n, sodium_base64_VARIANT_URLSAFE_NO_PADDING);

            std::vector<char> b64_cstr(b64_size);
            std::string       new_name;
            randombytes_buf(bytes, n);
            sodium_bin2base64(b64_cstr.data(), b64_size, bytes, n, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
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

    bool is_username_occupied(const std::string& uname)
    {
        return (uname_uemail.find(uname) != uname_uemail.end());
    }

    // Have to use pointer to avoid exception handling.
    const std::string* get_uemail_by_uname(const std::string& uname)
    {
        auto it = uname_uemail.find(uname);
        if (it == uname_uemail.end())
            return nullptr;
        return &(it->second);
    }

    // Have to use pointer to avoid exception handling.
    const std::string* get_uname_by_uemail(const std::string& uemail)
    {
        auto it = user_db.find(uemail);
        if (it == user_db.end())
            return nullptr;
        return &(it->second.unique_name);
    }

    user_item* get_user_item_by_uemail(const std::string& uemail)
    {
        auto it = user_db.find(uemail);
        if (it == user_db.end())
            return nullptr;
        return &(it->second);
    }

    user_item* get_user_item_by_uname(const std::string& uname)
    {
        auto uemail_ptr = get_uemail_by_uname(uname);
        if (uemail_ptr == nullptr)
            return nullptr;
        return get_user_item_by_uemail(*uemail_ptr);
    }

    auto get_total_user_num()
    {
        return user_db.size();
    }

    bool add_user(const std::string& uemail, std::string& uname, std::string& user_password, uint8_t& err, bool& is_uname_randomized)
    {
        err                 = 0;
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
        new_user.unique_name  = uname;
        new_user.pass_hash    = hashed_pass;
        user_db.insert({uemail, new_user});
        uname_uemail.insert({uname, uemail});
        user_list_fmt += (uname + " (" + uemail + ") " + "\n");
        std::ofstream file_out(db_file_path, std::ios::binary | std::ios::app);
        if (!file_out.is_open()) {
            err = 13;
            return false;
        }
        size_t               bytes_to_write = 1 + uemail.size() + 1 + uname.size() + hashed_pass.size();
        size_t               offset         = 0;
        std::vector<uint8_t> block(bytes_to_write);
        block[0] = static_cast<uint8_t>(uemail.size() - 1);
        ++offset;
        std::copy(uemail.begin(), uemail.end(), block.begin() + offset);
        offset += uemail.size();
        block[offset] = static_cast<uint8_t>(uname.size());
        ++offset;
        std::copy(uname.begin(), uname.end(), block.begin() + offset);
        offset += uname.size();
        std::copy(hashed_pass.begin(), hashed_pass.end(), block.begin() + offset);
        file_out.write(reinterpret_cast<char*>(block.data()), block.size());
        if (file_out.fail()) {
            err = 13;
            return false;
        }
        return true;
    }

    // type = 0: uemail + password
    // type = 1 (or others): uname + password
    bool user_pass_check(const uint8_t type, const std::string& str, std::string& password, uint8_t& err)
    {
        user_item* ptr_item = nullptr;
        err                 = 0;
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
        auto ret = (crypto_pwhash_str_verify((ptr_item->pass_hash).data(), password.c_str(), password.size()) == 0);

        password.clear();
        if (!ret)
            err = 8;
        return ret;
    }

    std::string& get_user_list()
    {
        return user_list_fmt;
    }

    std::string get_user_list(bool show_status)
    {
        if (!show_status)
            return get_user_list();
        std::string list_with_status;
        for (auto& it : user_db) {
            if (it.second.user_status == 1)
                list_with_status += (it.second.unique_name + " (" + it.second.unique_email + ") (in)\n");
            else
                list_with_status += ((it.second.unique_name) + " (" + it.second.unique_email + ")\n");
        }
        return list_with_status;
    }

    user_item* get_user_item(const uint8_t type, const std::string& str)
    {
        if (type == 0x00)
            return get_user_item_by_uemail(str);
        else
            return get_user_item_by_uname(str);
    }

    // type = 0: uemail
    // type = 1 (or others): uname
    bool bind_user_ctx(const uint8_t type, const std::string& str, const uint64_t& cif)
    {
        auto ptr_user = get_user_item(type, str);
        if (ptr_user == nullptr)
            return false;
        ptr_user->user_status = 1;
        ptr_user->bind_cif    = cif;
        return true;
    }

    bool unbind_user_ctx(const uint8_t type, const std::string& str)
    {
        user_item* ptr_item = nullptr;
        auto       ptr_user = get_user_item(type, str);
        if (ptr_item == nullptr)
            return false;
        ptr_item->user_status = 0;
        ptr_item->bind_cif    = 0;
        return true;
    }

    bool get_bind_cif(const uint8_t type, const std::string& str, uint64_t& cif)
    {
        auto ptr_user = get_user_item(type, str);
        if (ptr_user == nullptr)
            return false;
        if (ptr_user->user_status == 0)
            return false;
        cif = ptr_user->bind_cif;
        return true;
    }

    std::pair<size_t, size_t> get_user_stat()
    {
        size_t in = 0;
        for (auto& it : user_db) {
            if (it.second.user_status == 1)
                ++in;
        }
        return std::make_pair(get_total_user_num(), in);
    }
};