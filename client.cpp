#include "lc_common.hpp"
#include "lc_keymgr.hpp"
#include "lc_consts.hpp"
#include "lc_bufmgr.hpp"

#include <iostream>
#include <ncurses.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sodium.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <vector>
#include <cstring>      // For C string 
#include <algorithm>    // For std::find_if
#include <sstream>      // For stringstream
#include <unordered_map>
#include <chrono>
#include <stdexcept>
#include <iomanip>
#include <atomic>

constexpr size_t BOTTOM_HEIGHT = 3;
constexpr char welcome[] = "Welcome to LightChat Service (aka LiChat)!\n";
constexpr char prompt[] = "Enter Your message: ";

std::atomic<bool> thread_run;

class client_server_pk_mgr {
    std::string server_pk_dir;
    std::array<uint8_t, crypto_box_PUBLICKEYBYTES> server_crypto_pk;
    std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> server_sign_pk;
    bool status;

public:
    client_server_pk_mgr() : server_pk_dir(default_key_dir), status(false) {}
    client_server_pk_mgr(const std::string& dir) : server_pk_dir(dir), status(false) {}

    void set_dir(const std::string& dir) {
        server_pk_dir = dir;
    }

    const std::string& get_dir() const {
        return server_pk_dir;
    }

    bool read_server_pk(void) {
        std::vector<uint8_t> server_spk(crypto_sign_PUBLICKEYBYTES), server_cpk(crypto_box_PUBLICKEYBYTES);
        std::string server_spk_file = server_pk_dir + "/client_server_sign.pub";
        std::string server_cpk_file = server_pk_dir + "/client_server_crypto.pub";
        auto res1 = key_mgr_25519::read_key_file(server_cpk_file, server_cpk, crypto_box_PUBLICKEYBYTES);
        auto res2 = key_mgr_25519::read_key_file(server_spk_file, server_spk, crypto_sign_PUBLICKEYBYTES);
        if(res1 == 0 && res2 == 0) {
            std::copy(server_spk.begin(), server_spk.end(), server_sign_pk.begin());
            std::copy(server_cpk.begin(), server_cpk.end(), server_crypto_pk.begin());
            status = true;
            return true;
        }
        return false;
    }

    bool update_server_pk(const std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>& recved_spk, const std::array<uint8_t, crypto_box_PUBLICKEYBYTES>& recved_cpk) {
        std::string server_spk_file = server_pk_dir + "/client_server_sign.pub";
        std::string server_cpk_file = server_pk_dir + "/client_server_crypto.pub";
        std::ofstream out_spk(server_spk_file, std::ios::binary);
        std::ofstream out_cpk(server_cpk_file, std::ios::binary);
        if(!out_spk.is_open() || !out_cpk.is_open()) {
            if(out_spk.is_open()) out_spk.close();
            if(out_cpk.is_open()) out_cpk.close();
            return false;
        }    
        out_spk.write(reinterpret_cast<const char *>(recved_spk.data()), recved_spk.size());
        out_cpk.write(reinterpret_cast<const char *>(recved_cpk.data()), recved_cpk.size());
        out_spk.close();
        out_cpk.close();
        server_sign_pk = recved_spk;
        server_crypto_pk = recved_cpk;
        status = true;
        return true;
    }

    const std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>& get_server_spk() const {
        return server_sign_pk;
    }

    const std::array<uint8_t, crypto_box_PUBLICKEYBYTES>& get_server_cpk() const {
        return server_crypto_pk;
    }

    const bool is_ready() const {
        return status;  // If true, good to go, othersize not.
    }
};

class client_session {
    // Generated
    std::array<uint8_t, CID_BYTES> client_cid;

    // Read / Received
    std::array<uint8_t, crypto_aead_aes256gcm_KEYBYTES> aes256gcm_key;

    // Received
    std::array<uint8_t, SID_BYTES> server_sid;
    uint64_t cinfo_hash; 
    std::array<uint8_t, CIF_BYTES> cinfo_hash_bytes;
    
    struct sockaddr_in src_addr;   // the updated source_ddress. 
    //  0 - Empty: cid generated
    //  1 - Standby: client info sent, waiting for server response.
    //  2 - Prepared: server response received and good, sent ok waiting for server ok.
    //      cid + server_pk + aes256gcm_key + server_sid + cinfo_hash
    //  3 - Sent user credentials, waiting for server ok
    //  4 - Activated.
    int status; 
    bool is_server_key_req;

public:
    client_session() : status(0) {
        randombytes_buf(client_cid.data(), client_cid.size());
    }

    void sent_cinfo(const bool server_key_req) {
        status = 1;
        is_server_key_req = server_key_req;
    }

    const bool requested_server_key() {
        return is_server_key_req;
    }

    void reset() {
        randombytes_buf(client_cid.data(), client_cid.size());
        status = 0;
    }

    int prepare(const client_server_pk_mgr& server_pk_mgr, const key_mgr_25519& client_key, const std::array<uint8_t, SID_BYTES>& sid, const std::array<uint8_t, CIF_BYTES>& cif_bytes) {
        if(status != 1)
            return -1;  // Not quite possible
        if(!server_pk_mgr.is_ready() || !client_key.is_activated()) 
            return -3;  // key_mgr not activated
        uint64_t cif_calc = lc_utils::hash_client_info(client_cid, client_key.get_crypto_pk());
        uint64_t cif_recv = lc_utils::bytes_to_u64(cif_bytes);
        if(cif_calc != cif_recv) 
            return 1;  //  Need to report to server, msg error
        if(crypto_box_beforenm(aes256gcm_key.data(), server_pk_mgr.get_server_cpk().data(), client_key.get_crypto_sk().data()) != 0)
            return 3;  //  Need to report to server, msg error
        server_sid = sid;
        cinfo_hash = cif_recv;
        cinfo_hash_bytes = cif_bytes;
        status = 2;
        return 0;      
    }

    void activate() {
        status = 3;
    }

    void sent_auth() {
        status = 4;
    }

    void auth_ok() {
        status = 5;
    }

    void set_status(int s) {
        status = s;
    }

    const auto get_status() const {
        return status;
    }

    const auto& get_client_cid() const {
        return client_cid;
    }

    const auto& get_aes256gcm_key() const {
        return aes256gcm_key;
    }

    const auto& get_server_sid() const {
        return server_sid;
    }

    const auto& get_cinfo_hash() const {
        return cinfo_hash;
    }

    const auto& get_cinfo_hash_bytes() const {
        return cinfo_hash_bytes;
    }

    const auto& get_src_addr() const {
        return src_addr;
    }

    void update_src_addr(const struct sockaddr_in& addr) {
        src_addr = addr;
    }
};

class lichat_client {
    uint16_t server_port;
    struct sockaddr_in server_addr;
    int client_main_fd;
    int thread_recv_fd;
    client_server_pk_mgr server_pk_mgr;
    std::string key_dir;
    client_session session;
    key_mgr_25519 client_key;
    msg_buffer buffer;
    std::vector<std::string> messages;
    int last_error;

public:

    lichat_client() : 
    client_main_fd(-1), thread_recv_fd(-1), 
    server_pk_mgr(client_server_pk_mgr()), 
    key_dir(default_key_dir),
    session(client_session()), client_key(key_mgr_25519(key_dir, "client_")), 
    buffer(msg_buffer()), last_error(0) {
        server_port = DEFAULT_SERVER_PORT;
        server_addr.sin_addr.s_addr = inet_addr(DEFAULT_SERVER_ADDR);
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(server_port);
        // Store the initial addr to session.
        session.update_src_addr(server_addr);
    }

    bool set_server_addr(std::string& addr_str, std::string& port_str) {
        std::array<char, INET_ADDRSTRLEN> ipv4_addr;
        uint16_t port_num;
        if(!lc_utils::get_addr_info(addr_str, ipv4_addr) || !lc_utils::string_to_u16(port_str, port_num)) 
            return false;
        server_port = port_num;
        server_addr.sin_addr.s_addr = inet_addr(ipv4_addr.data());
        server_addr.sin_port = htons(port_num);
        session.update_src_addr(server_addr);
        return true;
    }

    std::string parse_server_auth_error(const uint8_t err_code) {
        if(err_code == 1)
            return "E-mail format error.";
        else if(err_code == 3)
            return "E-mail already signed up.";
        else if(err_code == 5)
            return "Username format error.";
        else if(err_code == 7)
            return "Password format error.";
        else if(err_code == 9)
            return "Failed to hash your password.";
        else if(err_code == 11)
            return "Failed to randomize your username.";

        else if(err_code == 2) 
            return "E-mail not signed up.";
        else if(err_code == 4)
            return "Username not signed up.";
        else if(err_code == 6)
            return "Server internal error.";
        else if(err_code == 8)
            return "Password incorrect.";
        
        else
            return "Unknown server error.";
    }

    void thread_recv_print(WINDOW *win, int& thread_err) {
        thread_err = 0;
        if(win == nullptr) {
            thread_err = 1;
            return;
        }
        if(thread_recv_fd < 0) {
            thread_err = 3;
            return;
        }
        struct sockaddr_in src_addr;
        while(thread_run) {
            auto bytes = wait_server_response(src_addr);
            if(!decrypt_recv_0x10raw_bytes(bytes))
                continue;
            std::string str(reinterpret_cast<const char*>(buffer.recv_aes_buffer.data()), buffer.recv_aes_bytes);
            messages.push_back(str);


        }
            
    }

    // Close server and possible FD
    bool close_client(int err) {
        last_error = err;
        if(client_main_fd != -1) {
            close(client_main_fd); 
            client_main_fd = -1;
        }
        if(thread_recv_fd != -1) {
            close(thread_recv_fd);
            thread_recv_fd = -1;
        }
        return err == 0;
    }

    int get_last_error(void) {
        return last_error;
    }
    
    bool start_client(void) {
        if(client_key.key_mgr_init() != 0) {
            std::cout << "Key manager not activated. @ START." << std::endl;
            return close_client(1);
        }
        client_main_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if(client_main_fd < 0) 
            return close_client(3);
        std::cout << "lichat client started." << std::endl;
        return true;
    }

    std::vector<uint8_t> assemble_user_info(const bool is_signup, const bool is_login_uemail, const std::string& uemail, const std::string& uname, const std::string& password) {
        size_t vec_size = 0, offset = 0;
        if(is_signup) {
            vec_size = 1 + 1 + uemail.size() + 1 + uname.size() + 1 + password.size() + 1;
            std::vector<uint8_t> vec(vec_size, 0x00);
            offset += 2;
            vec.insert(vec.begin() + offset, uemail.begin(), uemail.end());
            offset += (uemail.size() + 1);
            vec.insert(vec.begin() + offset, uname.begin(), uname.end());
            offset += (uname.size() + 1);
            vec.insert(vec.begin() + offset, password.begin(), password.end());
            return vec;
        }   
        if(is_login_uemail) 
            vec_size = 1 + 1 + uemail.size() + 1 + password.size() + 1;
        else
            vec_size = 1 + 1 + uname.size() + 1 + password.size() + 1;
        std::vector<uint8_t> vec(vec_size);
        vec[0] = 0x01;
        if(is_login_uemail) {
            vec[1] = 0x00;
            offset += 2;
            vec.insert(vec.begin() + offset, uemail.begin(), uemail.end());
            offset += uemail.size() + 1;
        }
        else {
            vec[1] = 0x01;
            offset += 2;
            vec.insert(vec.begin() + offset, uname.begin(), uname.end());
            offset += uname.size() + 1;
        }
        vec.insert(vec.begin() + offset, password.begin(), password.end());
        return vec;
    }

    void print_menu(void) {
        std::cout << main_menu << std::endl;
    }

    int simple_send(const client_session& curr_s, const uint8_t *buf, size_t n) {
        auto addr = curr_s.get_src_addr();
        return sendto(client_main_fd, buf, n, 0, (const struct sockaddr*)(&addr), sizeof(addr));
    }

    // Simplify the socket send function.
    // Format : 1-byte header + 
    //          cinfo_hash +
    //          aes_nonce + 
    //          aes_gcm_encrypted (sid + msg_body)
    int simple_secure_send(const uint8_t header, const client_session& curr_s, const uint8_t *raw_msg, size_t raw_n) {
        if(curr_s.get_status() == 0 || curr_s.get_status() == 1) 
            return -1;

        if((1 + CIF_BYTES + crypto_aead_aes256gcm_NPUBBYTES + SID_BYTES + raw_n + crypto_aead_aes256gcm_ABYTES) > BUFF_SIZE) 
            return -3;

        auto aes_key = curr_s.get_aes256gcm_key();
        auto cif = curr_s.get_cinfo_hash();
        auto cif_bytes = lc_utils::u64_to_bytes(cif);
        auto sid = curr_s.get_server_sid();

        std::array<uint8_t, crypto_aead_aes256gcm_NPUBBYTES> client_aes_nonce;
        size_t offset = 0, aes_encrypted_len = 0;

        // Padding the first byte
        buffer.send_buffer[0] = header;
        ++ offset;
        
        // Padding the cinfo_hash
        std::copy(cif_bytes.begin(), cif_bytes.end(), buffer.send_buffer.begin() + offset);
        offset += cif_bytes.size();

        // Padding the aes_nonce
        lc_utils::generate_aes_nonce(client_aes_nonce);
        std::copy(client_aes_nonce.begin(), client_aes_nonce.end(), buffer.send_buffer.begin() + offset);
        offset += client_aes_nonce.size();

        if((offset + sid.size() + raw_n + crypto_aead_aes256gcm_ABYTES) > BUFF_SIZE) {
            buffer.send_bytes = offset;
            return -3; // buffer overflow occur.
        }

        // Construct the raw message: sid + cif + msg_body
        std::copy(sid.begin(), sid.end(), buffer.send_aes_buffer.begin());
        std::copy(raw_msg, raw_msg + raw_n, buffer.send_aes_buffer.begin() + sid.size());
        // Record the buffer occupied size.
        buffer.send_aes_bytes = sid.size() + raw_n;

        // AES encrypt and padding to the send_buffer.
        auto res = crypto_aead_aes256gcm_encrypt(
            buffer.send_buffer.data() + offset, 
            (unsigned long long *)&aes_encrypted_len,
            (const uint8_t *)buffer.send_aes_buffer.data(),
            buffer.send_aes_bytes, 
            NULL, 0, NULL, 
            client_aes_nonce.data(), aes_key.data()
        );
        buffer.send_bytes = offset + aes_encrypted_len;
        if(res != 0) 
            return -5;
        auto ret = simple_send(curr_s, buffer.send_buffer.data(), buffer.send_bytes);
        if(ret < 0) 
            return -7;
        return ret;
    }

    bool decrypt_recv_0x10raw_bytes(const ssize_t recved_raw_bytes) {
        if(recved_raw_bytes < lc_utils::calc_encrypted_len(1))
            return false;
        auto aes_key = session.get_aes256gcm_key();
        std::array<uint8_t, crypto_aead_aes256gcm_NPUBBYTES> aes_nonce;
        std::array<uint8_t, SID_BYTES> sid;
        std::array<uint8_t, CIF_BYTES> cif_bytes;
        auto begin = buffer.recv_raw_buffer.begin();
        size_t offset = 0; // Omit first byte 0x10.
        unsigned long long aes_decrypted_len = 0;
        auto header = buffer.recv_raw_buffer[0];
        if(header != 0x10) 
            return false;
        ++ offset;
        std::copy(begin + offset, begin + offset + crypto_aead_aes256gcm_NPUBBYTES, aes_nonce.begin());
        offset += crypto_aead_aes256gcm_NPUBBYTES;
        auto ret = 
            (crypto_aead_aes256gcm_decrypt(
                buffer.recv_aes_buffer.begin(), &aes_decrypted_len, NULL,
                begin + offset, recved_raw_bytes - offset,
                NULL, 0,
                aes_nonce.data(), aes_key.data()
            ) == 0);
        buffer.recv_aes_bytes = aes_decrypted_len;
        if(aes_decrypted_len <= SID_BYTES + CIF_BYTES)
            return false;
        return ret;
    }

    ssize_t wait_server_response(struct sockaddr_in& addr) {
        buffer.clear_buffer();
        struct sockaddr_in src_addr;
        auto addr_len = sizeof(src_addr);
        auto ret = recvfrom(client_main_fd, buffer.recv_raw_buffer.data(), buffer.recv_raw_buffer.size(), MSG_WAITALL, (struct sockaddr *)(&src_addr), (socklen_t *)&addr_len);
        addr = src_addr;
        return ret;
    }

    bool user_input(const std::string& prompt, std::string& dest_str, size_t max_times, 
        const std::function<int(const std::string&)>& fmt_check_func) {
        size_t retry = 0;
        bool fmt_correct = false;
        std::cout << prompt;
        while(retry < max_times) {
            std::getline(std::cin, dest_str);
            ++ retry;
            if(fmt_check_func(dest_str) != 0) {
                std::cout << "Invalid format. Please retry (" << retry << '/' << max_times << ")." << std::endl;
            }
            else {
                fmt_correct = true;
                break;
            }  
        }
        if(retry == max_times && !fmt_correct) {
            std::cout << "Too many input failures. Abort." << std::endl;
            return false;
        }
        else {
            return true;
        }
    }

    bool sign_cid_cpk(std::array<uint8_t, crypto_sign_BYTES + CID_BYTES + crypto_box_PUBLICKEYBYTES>& signed_cid_cpk) {
        if(!client_key.is_activated())
            return false;
        auto client_ssk = client_key.get_sign_sk();
        auto client_cid = session.get_client_cid();
        auto client_cpk = client_key.get_crypto_pk();
        std::array<uint8_t, CID_BYTES + crypto_box_PUBLICKEYBYTES> cid_cpk;
        unsigned long long signed_len;
        std::copy(client_cid.begin(), client_cid.end(), cid_cpk.begin());
        std::copy(client_cpk.begin(), client_cpk.end(), cid_cpk.begin() + client_cid.size());
        if(crypto_sign(signed_cid_cpk.data(), &signed_len, cid_cpk.data(), cid_cpk.size(), client_ssk.data()) != 0) 
            return false;
        return true;
    }
    
    bool run_client(void) {
        if(!client_key.is_activated()) {
            std::cout << "Key manager not activated." << std::endl;
            last_error = 1;
            return false;
        }
        if(client_main_fd == -1) {
            std::cout << "Client not started." << std::endl;
            last_error = 3;
            return false;
        }
        std::array<uint8_t, crypto_aead_aes256gcm_NPUBBYTES> server_aes_nonce;
        std::array<uint8_t, crypto_aead_aes256gcm_KEYBYTES> aes_key;
        //std::array<uint8_t, SID_BYTES> server_sid;
        std::array<uint8_t, CIF_BYTES> recved_cif_bytes;
        std::array<uint8_t, SID_BYTES> recved_server_sid;
        std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> recved_server_spk;
        std::array<uint8_t, crypto_box_PUBLICKEYBYTES> recved_server_cpk;
        struct sockaddr_in msg_addr;
        size_t aes_encrypted_len = 0;
        size_t aes_decrypted_len = 0;
        size_t offset = 0;

        while(true) {
            auto status = session.get_status(); 
            if(status == 0) {
                auto read_pk = server_pk_mgr.read_server_pk();
                offset = 0;
                if(!read_pk) 
                    buffer.send_buffer[0] = 0x00;
                else 
                    buffer.send_buffer[0] = 0x01;
                ++ offset;
                auto client_spk = client_key.get_sign_pk();
                std::copy(client_spk.begin(), client_spk.end(), buffer.send_buffer.begin() + offset);
                offset += client_spk.size();
                std::array<uint8_t, crypto_sign_BYTES + CID_BYTES + crypto_box_PUBLICKEYBYTES> signed_cid_cpk;
                if(!sign_cid_cpk(signed_cid_cpk)) {
                    last_error = 5;
                    return false;
                }
                std::copy(signed_cid_cpk.begin(), signed_cid_cpk.end(), buffer.send_buffer.begin() + offset);
                buffer.send_bytes = offset + signed_cid_cpk.size();
                simple_send(session, buffer.send_buffer.data(), buffer.send_bytes);
                session.sent_cinfo((buffer.send_buffer[0] == 0x00)); // 0x00: requested server key, 0x01: not requested server key
                continue;
            }
            if(status == 1 || status == 2 || status == 4) {
                buffer.recv_raw_bytes = wait_server_response(msg_addr);
                if(buffer.recved_insuff_bytes(CLIENT_RECV_MIN_BYTES) || buffer.recved_overflow()) 
                    continue; // If size is invalid, ommit.
                if(status == 1) {
                    offset = 0;
                    auto header = buffer.recv_raw_buffer[0];
                    auto beg = buffer.recv_raw_buffer.begin();
                    ++ offset;
                    if((buffer.recv_raw_bytes == sizeof(server_ff_failed)) && (std::memcmp(beg, server_ff_failed, sizeof(server_ff_failed)) == 0)) {
                        session.reset();
                        continue;
                    }
                    if(header != 0x00 && header != 0x01)
                        continue;
                    unsigned long long unsign_len = 0;
                    if(header == 0x00) {
                        if(!session.requested_server_key())
                            continue;
                        size_t expected_len = 1 + crypto_sign_PUBLICKEYBYTES + 
                                              crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES +
                                              crypto_aead_aes256gcm_NPUBBYTES + SID_BYTES + CIF_BYTES + 
                                              sizeof(ok) + crypto_aead_aes256gcm_ABYTES;
                        if(buffer.recv_raw_bytes != expected_len)
                            continue;
                        std::copy(beg + offset, beg + offset + crypto_sign_PUBLICKEYBYTES, recved_server_spk.begin());
                        offset += recved_server_spk.size();
                        if(crypto_sign_open(nullptr, &unsign_len, beg + offset, 
                            crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES, recved_server_spk.data()) != 0) 
                            continue;
                        offset += crypto_sign_BYTES;
                        std::copy(beg + offset, beg + offset + crypto_box_PUBLICKEYBYTES, recved_server_cpk.begin());
                        offset += crypto_box_PUBLICKEYBYTES;
                        if(!server_pk_mgr.update_server_pk(recved_server_spk, recved_server_cpk)) {
                            last_error = 5;
                            return false;
                        }
                    }
                    else {
                        if(session.requested_server_key())
                            continue;
                        size_t expected_len = 1 + crypto_sign_BYTES + sizeof(ok) +
                                              crypto_aead_aes256gcm_NPUBBYTES + SID_BYTES + CIF_BYTES + 
                                              sizeof(ok) + crypto_aead_aes256gcm_ABYTES;
                        if(buffer.recv_raw_bytes != expected_len)
                            continue;
                        if(crypto_sign_open(nullptr, &unsign_len, beg + offset, 
                            crypto_sign_BYTES + sizeof(ok), server_pk_mgr.get_server_spk().data()) != 0) 
                            continue;
                        offset += crypto_sign_BYTES + sizeof(ok);
                    }
                    std::copy(beg + offset, beg + offset + crypto_aead_aes256gcm_NPUBBYTES, server_aes_nonce.begin());
                    offset += crypto_aead_aes256gcm_NPUBBYTES;
                    if(lc_utils::calc_aes_key(aes_key, server_pk_mgr.get_server_cpk(), client_key.get_crypto_sk()) != 0)
                        continue;
                    
                    auto is_aes_ok = 
                        (crypto_aead_aes256gcm_decrypt(
                            buffer.recv_aes_buffer.begin(), (unsigned long long *)(&aes_decrypted_len),
                            NULL,
                            beg + offset, SID_BYTES + CIF_BYTES + sizeof(ok) + crypto_aead_aes256gcm_ABYTES,
                            NULL, 0,
                            server_aes_nonce.data(), aes_key.data()
                        ) == 0);

                    buffer.recv_aes_bytes = aes_decrypted_len;
                    auto is_msg_ok = ((aes_decrypted_len == SID_BYTES + CIF_BYTES + sizeof(ok)) && 
                    (std::memcmp(buffer.recv_aes_buffer.begin() + SID_BYTES + CIF_BYTES, ok, sizeof(ok)) == 0));
                    auto aes_beg = buffer.recv_aes_buffer.begin();
                    if(is_aes_ok && is_msg_ok) {
                        session.update_src_addr(msg_addr);
                        std::copy(aes_beg, aes_beg + SID_BYTES, recved_server_sid.begin());
                        std::copy(aes_beg + SID_BYTES, aes_beg + SID_BYTES + CIF_BYTES, recved_cif_bytes.begin());
                        auto ret = session.prepare(server_pk_mgr, client_key, recved_server_sid, recved_cif_bytes);
                        if(ret == 0) {
                            simple_secure_send(0x02, session, ok, sizeof(ok));
                            std::cout << "Secure session prepared OK!\t" << session.get_status() << std::endl;
                            continue;
                        }
                        else if(ret < 0) {
                            last_error = 7;
                            return false;
                        }
                        is_msg_ok = false;
                    }
                    offset = 0;
                    if(!is_aes_ok) {
                        buffer.send_buffer[0] = 0xEF;
                        std::copy(std::begin(client_ef_keyerr), std::end(client_ef_keyerr), buffer.send_buffer.begin() + 1);
                    }
                    else {
                        buffer.send_buffer[0] = 0xDF;
                        std::copy(std::begin(client_df_msgerr), std::end(client_df_msgerr), buffer.send_buffer.begin() + 1);
                    }
                    offset += (1 + ERR_CODE_BYTES);
                    auto client_spk = client_key.get_sign_pk();
                    std::copy(client_spk.begin(), client_spk.end(), buffer.send_buffer.begin() + offset);
                    offset += client_spk.size();
                    std::array<uint8_t, crypto_sign_BYTES + CID_BYTES + crypto_box_PUBLICKEYBYTES> signed_cid_cpk;
                    if(!sign_cid_cpk(signed_cid_cpk)) {
                        last_error = 5;
                        return false;
                    }
                    std::copy(signed_cid_cpk.begin(), signed_cid_cpk.end(), buffer.send_buffer.begin() + offset);
                    buffer.send_bytes = offset + signed_cid_cpk.size();
                    simple_send(session, buffer.send_buffer.data(), buffer.send_bytes);
                    session.reset();
                    continue;
                }
                if(status == 2) {
                    offset = 0;
                    auto header = buffer.recv_raw_buffer[0];
                    auto beg = buffer.recv_raw_buffer.begin();
                    // 1 + 6-byte err + CIF + deleted_sid + server_sign_pk + signed(server_cpk)
                    size_t expected_err_size = 1 + ERR_CODE_BYTES + CIF_BYTES + SID_BYTES + 
                        crypto_sign_PUBLICKEYBYTES + crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES;

                    if(buffer.recv_raw_bytes == expected_err_size) {
                        if(std::memcmp(beg, server_ef_keyerr, sizeof(server_ef_keyerr) == 0) || 
                            std::memcmp(beg, server_df_msgerr, sizeof(server_df_msgerr) == 0)) {
                            offset += 1 + ERR_CODE_BYTES;
                            std::copy(beg + offset, beg + offset + CIF_BYTES, recved_cif_bytes.begin());
                            offset += CIF_BYTES;
                            std::copy(beg + offset, beg + offset + SID_BYTES, recved_server_sid.begin());
                            offset += SID_BYTES;
                            if(recved_cif_bytes == session.get_cinfo_hash_bytes() && session.get_server_sid() == recved_server_sid) {
                                std::copy(beg + offset, beg + offset + crypto_sign_PUBLICKEYBYTES, recved_server_spk.begin());
                                offset += crypto_sign_PUBLICKEYBYTES + crypto_sign_BYTES;
                                std::copy(beg + offset, beg + offset + crypto_box_PUBLICKEYBYTES, recved_server_cpk.begin());
                                server_pk_mgr.update_server_pk(recved_server_spk, recved_server_cpk);
                                session.reset();
                                continue;
                            }
                        }
                    }
                    offset = 0;
                    if(header != 0x02) 
                        continue; // Now, only handles 0x02 header.
                        // Expected: 0x02 + aes_nonce + encrypted(sid + cif + ok + checksum)
                    ++ offset;
                    size_t expected_ok_size = 1 + crypto_aead_aes256gcm_NPUBBYTES + 
                        SID_BYTES + CIF_BYTES + + sizeof(ok) + crypto_aead_aes256gcm_ABYTES;
                    if(buffer.recv_raw_bytes != expected_ok_size)
                        continue; // Invalid message length.
                    std::copy(beg + offset, beg + offset + crypto_aead_aes256gcm_NPUBBYTES, server_aes_nonce.begin());
                    offset += crypto_aead_aes256gcm_NPUBBYTES;
                    auto is_aes_ok = 
                        (crypto_aead_aes256gcm_decrypt(
                            buffer.recv_aes_buffer.begin(), (unsigned long long *)(&aes_decrypted_len),
                            NULL,
                            beg + offset, SID_BYTES + CIF_BYTES + sizeof(ok) + crypto_aead_aes256gcm_ABYTES,
                            NULL, 0,
                            server_aes_nonce.data(), session.get_aes256gcm_key().data()
                        ) == 0);
                    buffer.recv_aes_bytes = aes_decrypted_len;
                    if(!is_aes_ok)
                        continue; // Invalid key, probably not from the previous server.
                    if(std::memcmp(buffer.recv_aes_buffer.begin() + SID_BYTES + CIF_BYTES, ok, sizeof(ok)) != 0)
                        continue; // Not expected message ok.
                    session.update_src_addr(msg_addr);
                    session.activate(); // status already is confirmed as 2, so activate would always be true.
                    std::cout << "Secure session activated OK!\t" << session.get_status() << std::endl;
                    continue; 
                }
                // Now status == 4
                if(buffer.recv_raw_bytes < lc_utils::calc_encrypted_len(1) || buffer.recv_raw_bytes > lc_utils::calc_encrypted_len(UNAME_MAX_BYTES))
                    continue;
                if(buffer.recv_raw_buffer[0] != 0x10)
                    continue;
                if(!decrypt_recv_0x10raw_bytes(buffer.recv_raw_bytes))
                    continue;
                auto aes_beg = buffer.recv_aes_buffer.begin();
                std::copy(aes_beg, aes_beg + SID_BYTES, recved_server_sid.begin());
                std::copy(aes_beg + SID_BYTES, aes_beg + SID_BYTES + CIF_BYTES, recved_cif_bytes.begin());
                if(recved_cif_bytes != session.get_cinfo_hash_bytes() || recved_server_sid != session.get_server_sid())
                    continue;
                auto msg_body = aes_beg + SID_BYTES + CIF_BYTES;
                auto msg_size = buffer.recv_aes_bytes - SID_BYTES - CIF_BYTES;
                if(msg_size < 1 || msg_size > UNAME_MAX_BYTES)
                    continue;
                if(msg_size == 1) {
                    std::cout << "Auth failed and rejected by the server." << std::endl;
                    std::cout << parse_server_auth_error(*msg_body) << std::endl;
                    session.set_status(3);
                    break;
                }
                else if(msg_size == 2 && std::memcmp(msg_body, ok, sizeof(ok))== 0) {
                    std::cout << "Auth succeeded by the server." << std::endl;
                    session.auth_ok();
                    break;
                }
                else {
                    std::cout << "Auth succeeded by the server with a randomized username." << std::endl;
                    std::cout << "Please *DO* remember this username: " << std::string(reinterpret_cast<char *>(msg_body), msg_size) << std::endl;
                    session.auth_ok();
                    break;
                }
            }
            if(status == 3) {
                std::string option, login_type, uemail, uname, password;
                if(!user_input(main_menu, option, CLIENT_INPUT_RETRY, [](const std::string& op) {
                    if(op == "1" || op == "2" || op == "signup" || op == "signin") return 0;
                        return 1;
                })) continue;
                if(option == "1" || option == "signup") { // Signing up, require email, username & password
                    if(!user_input(input_email, uemail, CLIENT_INPUT_RETRY, lc_utils::email_fmt_check))
                        continue;
                    if(!user_input(input_username, uname, CLIENT_INPUT_RETRY, lc_utils::user_name_fmt_check))
                        continue;
                    if(!user_input(input_password, password, CLIENT_INPUT_RETRY, lc_utils::pass_fmt_check))
                        continue;
                }
                else {
                    if(!user_input(choose_login, login_type, CLIENT_INPUT_RETRY, [](const std::string& op) {
                        if(op == "1" || op == "2" || op == "email" || op == "username") return 0;
                        return 1;
                    })) continue;

                    if(login_type == "1" || login_type == "email") {
                        if(!user_input(input_email, uemail, CLIENT_INPUT_RETRY, lc_utils::email_fmt_check))
                            continue;
                    }
                    else {
                        if(!user_input(input_username, uname, CLIENT_INPUT_RETRY, lc_utils::user_name_fmt_check))
                            continue;
                    }
                    if(!user_input(input_password, password, CLIENT_INPUT_RETRY, lc_utils::pass_fmt_check))
                        continue;
                }
                auto user_info = assemble_user_info(
                    (option == "1" || option == "signup"), 
                    (login_type == "1" || login_type == "email"),
                    uemail, uname, password);
                simple_secure_send(0x10, session, user_info.data(), user_info.size());
                session.sent_auth();
                continue;
            }
        }
        getchar();
        thread_recv_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if(thread_recv_fd < 0) {
            std::cout << "Failed to start a receiver socket." << std::endl;
            return close_client(9);
        }
        thread_run = true;
        setlocale(LC_ALL, "");
        initscr();
        cbreak();
        noecho();
        int height = 0, width = 0;
        getmaxyx(stdscr, height, width);
        WINDOW *top_win = newwin(height - BOTTOM_HEIGHT, width, 0, 0);
        WINDOW *bottom_win = newwin(3, width, height - BOTTOM_HEIGHT, 0);
        if(!top_win || !bottom_win) {
            std::cerr << "Failed to create windows." << std::endl;
            if(top_win) delwin(top_win);
            if(bottom_win) delwin(bottom_win);
            endwin();
            return close_client(11);;
        }
        keypad(bottom_win, TRUE);
        scrollok(top_win, TRUE);
        scrollok(bottom_win, TRUE);
        wprintw(top_win, welcome);
        wrefresh(top_win);
        wprintw(bottom_win, prompt);
        wrefresh(bottom_win);

        wgetch(bottom_win);


        delwin(top_win);
        delwin(bottom_win);
        endwin();
    }
};

int main(int argc, char **argv) {
    lichat_client new_client;
    if(sodium_init() < 0) {
        std::cout << "Failed to init libsodium." << std::endl;
        return 1;
    }
    if(argc >= 3) {
        std::string addr_str(argv[1]);
        std::string port_str(argv[2]);
        std::cout << "Trying to connect to server " << addr_str << ":" << port_str << std::endl;
        if(!new_client.set_server_addr(addr_str, port_str)) {
            std::cout << "Warning: Failed to connect to server " << addr_str << ":" << port_str << std::endl;
            std::cout << "Warning: Will use the default server localhost:8081." << std::endl;
        }
        else {
            std::cout << "Will connect to the provided server " << addr_str << ":" << port_str << std::endl;
        }
    }
    else {
        std::cout << "Will use the default server localhost:8081." << std::endl;
    }
    
    if(!new_client.start_client()) {
        std::cout << "Failed to start client. Error Code: " 
                  << new_client.get_last_error() << std::endl;
        return 3;
    }
    return new_client.run_client();
}