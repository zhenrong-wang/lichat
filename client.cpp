/*
 * Copyright (C) 2022-present Zhenrong WANG
 * This code is distributed under the license: MIT License
 * mailto: zhenrongwang@live.com | X/Twitter: wangzhr4
 */

#include "lc_common.hpp"
#include "lc_keymgr.hpp"
#include "lc_consts.hpp"
#include "lc_bufmgr.hpp"
#include "lc_strings.hpp"
#include "lc_winmgr.hpp"
#include "lc_long_msg.hpp"

#include <iostream>
#include <sys/socket.h>
#include <unistd.h>
#include <sodium.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <vector>
#include <cstring>    
#include <algorithm> 
#include <sstream> 
#include <unordered_map>
#include <chrono>
#include <stdexcept>
#include <iomanip>
#include <atomic>
#include <thread>
#include <functional>
#include <fcntl.h>
#include <errno.h>
#include <mutex>

std::atomic<bool> core_running(false);
std::atomic<bool> heartbeating(false);
std::atomic<bool> auto_signout(false);

std::atomic<bool> send_msg_req(false);
std::atomic<bool> send_gby_req(false);
std::atomic<bool> heartbeat_req(false);
std::atomic<bool> heartbeat_timeout(false);

std::atomic<time_t> last_heartbeat_sent(0);
std::atomic<time_t> last_heartbeat_recv(0);
std::atomic<time_t> last_lmsg_check(0);

std::string send_msg_body;
std::mutex mtx;

/**
 * This is the client core code. 
 * It could be integrated with a front-end class `window_mgr`
 * 
 * A window_mgr should provide methods:
 *  - init()                : initialize the window environment
 *  - set()                 : set attributes
 *  - err_to_string()       : convert error code to string
 *  - winput()              : handle user inputs in a loop
 *  - force_close()         : close the window environment
 *  - welcome_user()        : print welcome message
 *  - wprint_to_output()    : print message to the output window
 *  - fmt_prnt_msg()        : print messages in a formatted way
 * 
 * A window_mgr needs to include these global variables:
 *  - std::atomic<bool> send_msg_req
 *  - std::atomic<bool> send_gby_req
 *  - std::string send_msg_body
 *  - std::mutex mtx
 *  - std::atomic<bool> auto_signout
 *  - std::atomic<bool> heartbeat_timeout
 * 
 * Please refer to "lc_winmgr.hpp" for the default ncurses-based code.
 */

enum client_errors {
    NORMAL_RETURN = 0,
    CLIENT_KEY_MGR_ERROR,
    SOCK_FD_INVALID,
    SOCK_SETOPT_FAILED,
    HANDSHAKE_TIMEOUT,
    MSG_SIGNING_FAILED,
    SERVER_PK_MGR_ERROR,
    HASH_PASSWORD_FAILED,
    SESSION_PREP_FAILED,
    UNBLOCK_SOCK_FAILED,
    WINDOW_MGR_ERROR,
    CORE_ERROR,
};

enum core_errors {
    C_NORMAL_RETURN = 0,
    C_SOCK_FD_INVALID,
    C_HEARTBEAT_TIME_OUT,
    C_GOODBYE_SENT_ERR,
    C_HEARTBEAT_SENT_ERR,
    C_SOCKET_RECV_ERR,
};

const std::string heartbeat_timeout_msg = 
    "\nHeartbeat failed. Press any key to exit.\n";
const std::string client_exit_msg = 
    "[CLIENT] Will notify the server and exit.\n";
const std::string signed_out_msg = 
    "[CLIENT] Signed out. Press any key to exit.\n";
const std::string auto_signout_msg = 
    "Signed in on another client. Signed out here.\nPress any key to exit.\n";
const std::string send_gdy_failed = 
    "Failed to notify the server. Force exit.\n";
const std::string lmsg_recv_failed = 
    "Failed to receive long message.\n";

class curr_user {
    std::string unique_email;
    std::string unique_name;
    bool with_random_suffix;

public:
    curr_user () : with_random_suffix(false) {}
    
    void set_uemail (const std::string& str) {
        unique_email = str;
    }
    
    void set_uname (const std::string& str) {
        unique_name = str;
    }

    void set_suffix_flag (bool flag) {
        with_random_suffix = flag;
    }

    const std::string& get_uemail () const {
        return unique_email;
    }

    const std::string& get_uname () const {
        return unique_name;
    }

    const bool get_suffix_flag () const {
        return with_random_suffix;
    }
};

class client_server_pk_mgr {
    std::string server_pk_dir;
    std::array<uint8_t, crypto_box_PUBLICKEYBYTES> server_crypto_pk;
    std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> server_sign_pk;
    bool status;

public:
    client_server_pk_mgr () : server_pk_dir(default_key_dir), status(false) {}
    client_server_pk_mgr (const std::string& dir) : server_pk_dir(dir), 
        status(false) {}

    void set_dir (const std::string& dir) {
        server_pk_dir = dir;
    }

    const std::string& get_dir () const {
        return server_pk_dir;
    }

    bool read_server_pk (void) {
        std::vector<uint8_t> server_spk(crypto_sign_PUBLICKEYBYTES), 
                             server_cpk(crypto_box_PUBLICKEYBYTES);
        std::string server_spk_file = server_pk_dir + 
                                        "/client_server_sign.pub";
        std::string server_cpk_file = server_pk_dir + 
                                        "/client_server_crypto.pub";
        auto res1 = key_mgr_25519::read_key_file(server_cpk_file, server_cpk, 
                        crypto_box_PUBLICKEYBYTES);
        auto res2 = key_mgr_25519::read_key_file(server_spk_file, server_spk, 
                        crypto_sign_PUBLICKEYBYTES);
        if (res1 == 0 && res2 == 0) {
            std::copy(server_spk.begin(), server_spk.end(), 
                        server_sign_pk.begin());
            std::copy(server_cpk.begin(), server_cpk.end(), 
                        server_crypto_pk.begin());
            status = true;
            return true;
        }
        return false;
    }

    bool update_server_pk (
        const std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>& recved_spk, 
        const std::array<uint8_t, crypto_box_PUBLICKEYBYTES>& recved_cpk) {

        std::string server_spk_file = server_pk_dir + 
                                        "/client_server_sign.pub";
        std::string server_cpk_file = server_pk_dir + 
                                        "/client_server_crypto.pub";
        std::ofstream out_spk(server_spk_file, std::ios::binary);
        std::ofstream out_cpk(server_cpk_file, std::ios::binary);
        if (!out_spk.is_open() || !out_cpk.is_open()) {
            if (out_spk.is_open()) out_spk.close();
            if (out_cpk.is_open()) out_cpk.close();
            return false;
        }    
        out_spk.write(reinterpret_cast<const char *>(recved_spk.data()), 
                        recved_spk.size());
        out_cpk.write(reinterpret_cast<const char *>(recved_cpk.data()), 
                        recved_cpk.size());
        out_spk.close();
        out_cpk.close();
        server_sign_pk = recved_spk;
        server_crypto_pk = recved_cpk;
        status = true;
        return true;
    }

    const std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>& 
        get_server_spk () const {

        return server_sign_pk;
    }

    const std::array<uint8_t, crypto_box_PUBLICKEYBYTES>& 
        get_server_cpk () const {

        return server_crypto_pk;
    }

    const bool is_ready () const {
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
    client_session () : status(0), is_server_key_req(false) {
        randombytes_buf(client_cid.data(), client_cid.size());
    }

    void sent_cinfo (const bool server_key_req) {
        status = 1;
        is_server_key_req = server_key_req;
    }

    const bool requested_server_key () {
        return is_server_key_req;
    }

    void reset () {
        randombytes_buf(client_cid.data(), client_cid.size());
        status = 0;
    }

    int prepare (const client_server_pk_mgr& server_pk_mgr, 
        const key_mgr_25519& client_key, 
        const std::array<uint8_t, SID_BYTES>& sid, 
        const std::array<uint8_t, CIF_BYTES>& cif_bytes) {

        if (status != 1)
            return -1;  // Not quite possible
        if (!server_pk_mgr.is_ready() || !client_key.is_activated()) 
            return -3;  // key_mgr not activated
        uint64_t cif_calc = lc_utils::hash_client_info(client_cid, 
                            client_key.get_crypto_pk());
        uint64_t cif_recv = lc_utils::bytes_to_u64(cif_bytes);
        if (cif_calc != cif_recv) 
            return 1;  //  Need to report to server, msg error
        if (crypto_box_beforenm(aes256gcm_key.data(), 
            server_pk_mgr.get_server_cpk().data(), 
            client_key.get_crypto_sk().data()) != 0)
            return 3;  //  Need to report to server, msg error

        server_sid = sid;
        cinfo_hash = cif_recv;
        cinfo_hash_bytes = cif_bytes;
        status = 2;
        return 0;      
    }

    void activate () {
        status = 3;
    }

    void sent_auth () {
        status = 4;
    }

    void auth_ok () {
        status = 5;
    }

    void set_status (int s) {
        status = s;
    }

    const auto get_status () const {
        return status;
    }

    const auto& get_client_cid () const {
        return client_cid;
    }

    const auto& get_aes256gcm_key () const {
        return aes256gcm_key;
    }

    const auto& get_server_sid () const {
        return server_sid;
    }

    const auto& get_cinfo_hash () const {
        return cinfo_hash;
    }

    const auto& get_cinfo_hash_bytes () const {
        return cinfo_hash_bytes;
    }

    const auto& get_src_addr () const {
        return src_addr;
    }

    void update_src_addr (const struct sockaddr_in& addr) {
        src_addr = addr;
    }
};

class lichat_client {
    uint16_t server_port;
    struct sockaddr_in server_addr;
    int client_fd;
    client_server_pk_mgr server_pk_mgr;
    std::string key_dir;
    client_session session;
    key_mgr_25519 client_key;
    msg_buffer buffer;
    std::vector<std::string> messages;
    lmsg_send_pool lmsg_sends; 
    lmsg_recv_pool lmsg_recvs;
    curr_user user;
    window_mgr winmgr;
    int last_error;

public:

    lichat_client () : 
        client_fd(-1), server_pk_mgr(client_server_pk_mgr()), 
        key_dir(default_key_dir), session(client_session()), 
        client_key(key_mgr_25519(key_dir, "client_")), buffer(msg_buffer()), 
        user(curr_user()), winmgr(window_mgr()),
        last_error(0) {

        server_port = DEFAULT_SERVER_PORT;
        server_addr.sin_addr.s_addr = inet_addr(DEFAULT_SERVER_ADDR);
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(server_port);
        // Store the initial addr to session.
        session.update_src_addr(server_addr);
    }

    bool set_server_addr (std::string& addr_str, std::string& port_str) {
        std::array<char, INET_ADDRSTRLEN> ipv4_addr;
        uint16_t port_num;
        if (!lc_utils::get_addr_info(addr_str, ipv4_addr) || 
            !lc_utils::string_to_u16(port_str, port_num)) 
            return false;
        server_port = port_num;
        server_addr.sin_addr.s_addr = inet_addr(ipv4_addr.data());
        server_addr.sin_port = htons(port_num);
        session.update_src_addr(server_addr);
        return true;
    }

    std::string parse_server_auth_error (const uint8_t err_code) {
        if (err_code == 1)
            return "E-mail format error.";
        else if (err_code == 3)
            return "E-mail already signed up.";
        else if (err_code == 5)
            return "Username format error.";
        else if (err_code == 7)
            return "Password format error.";
        else if (err_code == 9)
            return "Failed to hash your password.";
        else if (err_code == 11)
            return "Failed to randomize your username.";

        else if (err_code == 2) 
            return "E-mail not signed up.";
        else if (err_code == 4)
            return "Username not signed up.";
        else if (err_code == 6)
            return "Server internal error.";
        else if (err_code == 8)
            return "Password incorrect.";
        
        else
            return "Unknown server error.";
    }

    std::string parse_core_err (const int& core_err) {
        if (core_err == C_NORMAL_RETURN) 
            return "Thread exit normally / gracefully.";
        else if (core_err == C_SOCK_FD_INVALID)
            return "The provided socket fd is invalid";
        else if (core_err == C_SOCKET_RECV_ERR) 
            return "Socket communication error.";
        else if (core_err == C_HEARTBEAT_SENT_ERR) 
            return "Failed to send heartbeat packets.";
        else if (core_err == C_GOODBYE_SENT_ERR) 
            return "Failed to send goodbye packet.";
        else if (core_err == C_HEARTBEAT_TIME_OUT)
            return "Heartbeat timeout.";
        else
            return "Unknown thread error. Possibly a bug.";
    }

    bool nonblock_socket () {
        int flags = fcntl(client_fd, F_GETFL, 0);
        if (flags == -1)
            return false;
        flags |= O_NONBLOCK;
        if (fcntl(client_fd, F_SETFL, flags) == -1)
            return false;
        return true;
    }

    static int simple_send_stc (const int fd, const client_session& curr_s, 
        const uint8_t *buf, size_t n) {
        auto addr = curr_s.get_src_addr();
        return sendto(fd, buf, n, 0, (const struct sockaddr*)(&addr), 
                      sizeof(addr));
    }
    // Simplify the socket send function.
    // Format : 1-byte header + 
    //          cinfo_hash +
    //          aes_nonce + 
    //          aes_gcm_encrypted (sid + msg_body)
    static int simple_secure_send_stc (const int fd, const uint8_t header, 
        const client_session& curr_s, msg_buffer& buff,
        const uint8_t *raw_msg, const size_t raw_n) {
            
        if (curr_s.get_status() == 0 || curr_s.get_status() == 1) 
            return -1;
        bool raw_msg_empty = false;
        size_t raw_bytes = raw_n;

        if (raw_msg == nullptr || raw_n == 0) {
            raw_msg_empty = true;
            raw_bytes = 0;
        }

        if ((1 + CIF_BYTES + crypto_aead_aes256gcm_NPUBBYTES + SID_BYTES + 
            raw_bytes + crypto_aead_aes256gcm_ABYTES) > BUFF_BYTES) 
            return -3;

        auto aes_key = curr_s.get_aes256gcm_key();
        auto cif = curr_s.get_cinfo_hash();
        auto cif_bytes = lc_utils::u64_to_bytes(cif);
        auto sid = curr_s.get_server_sid();

        std::array<uint8_t, crypto_aead_aes256gcm_NPUBBYTES> client_aes_nonce;
        size_t offset = 0, aes_enc_len = 0;

        // Padding the first byte
        buff.send_buffer[0] = header;
        ++ offset;
        
        // Padding the cinfo_hash
        std::copy(cif_bytes.begin(), cif_bytes.end(), 
                    buff.send_buffer.begin() + offset);
        offset += cif_bytes.size();

        // Padding the aes_nonce
        lc_utils::generate_aes_nonce(client_aes_nonce);
        std::copy(client_aes_nonce.begin(), client_aes_nonce.end(), 
                    buff.send_buffer.begin() + offset);
        offset += client_aes_nonce.size();
        std::copy(sid.begin(), sid.end(), buff.send_aes_buffer.begin());
        if (!raw_msg_empty) {
            std::copy(raw_msg, raw_msg + raw_bytes, 
                    buff.send_aes_buffer.begin() + sid.size());
        }
        // Record the buffer occupied size.
        buff.send_aes_bytes = sid.size() + raw_bytes;

        // AES encrypt and padding to the send_buffer.
        auto res = crypto_aead_aes256gcm_encrypt(
            buff.send_buffer.data() + offset, 
            reinterpret_cast<unsigned long long *>(&aes_enc_len),
            reinterpret_cast<const uint8_t *>(buff.send_aes_buffer.data()),
            buff.send_aes_bytes, 
            NULL, 0, NULL, 
            client_aes_nonce.data(), aes_key.data()
        );
        buff.send_bytes = offset + aes_enc_len;
        if (res != 0) 
            return -5;
        auto ret = simple_send_stc(fd, curr_s, buff.send_buffer.data(), 
                                   buff.send_bytes);
        if (ret < 0) 
            return -7;
        return ret;
    }

    static int simple_sign_send_stc (const int fd, const uint8_t header, 
        const client_session& curr_s, key_mgr_25519 k, msg_buffer& buff,
        const uint8_t *raw_msg, const size_t raw_n) {
        
        bool raw_msg_empty = false;
        size_t raw_bytes = raw_n;
        if (raw_msg == nullptr || raw_n == 0) {
            raw_msg_empty = true;
            raw_bytes = 0;
        }   
        if (curr_s.get_status() == 0 || curr_s.get_status() == 1) 
            return -1;
        if ((1 + crypto_sign_BYTES + CIF_BYTES + raw_bytes) > BUFF_BYTES) 
            return -3;
        
        auto cif = curr_s.get_cinfo_hash();
        auto cif_bytes = lc_utils::u64_to_bytes(cif);
        auto sign_sk = k.get_sign_sk();

        size_t offset = 0;
        unsigned long long sign_len = 0;

        // Padding the first byte
        buff.send_buffer[0] = header;
        ++ offset;
        std::vector<uint8_t> cif_msg(CIF_BYTES + raw_bytes);
        
        // Padding the cinfo_hash
        std::copy(cif_bytes.begin(), cif_bytes.end(), cif_msg.begin());
        if (!raw_msg_empty) 
            std::copy(raw_msg, raw_msg + raw_bytes, cif_msg.begin() + CIF_BYTES);

        auto res = crypto_sign(buff.send_buffer.begin() + offset,
                   &sign_len, cif_msg.data(), cif_msg.size(), sign_sk.data());
        buff.send_bytes = offset + sign_len;
        if (res != 0) 
            return -7;
        auto ret = simple_send_stc(fd, curr_s, buff.send_buffer.data(), 
                                   buff.send_bytes);
        return ret;
    }

    static bool pack_heartbeat (
        const std::array<uint8_t, CIF_BYTES>& cif_bytes,
        const std::array<uint8_t, crypto_sign_SECRETKEYBYTES>& client_sign_sk,
        std::array<uint8_t, HEARTBEAT_BYTES>& packet) {
        
        packet[0] = 0x1F;
        unsigned long long sign_len = 0;
        if (crypto_sign(packet.data() + 1, &sign_len, cif_bytes.data(), 
            cif_bytes.size(), client_sign_sk.data()) != 0) 
            return false;
        return true;
    }

    static void thread_heartbeat () {
        while (heartbeating) {
            auto now = lc_utils::now_time();
            if (now - last_heartbeat_recv >= HEARTBEAT_TIMEOUT_SECS) {
                heartbeat_timeout.store(true);
                return;
            }
            if ((now - last_heartbeat_sent) >= HEARTBEAT_INTERVAL_SECS) 
                heartbeat_req.store(true);
            std::this_thread::sleep_for(
                std::chrono::milliseconds(HEARTBEAT_THREAD_SLEEP_MS));
        }
    }

    static bool pack_goodbye (
        const std::array<uint8_t, CIF_BYTES>& cif_bytes,
        const std::array<uint8_t, crypto_sign_SECRETKEYBYTES>& client_sign_sk,
        std::array<uint8_t, GOODBYE_BYTES>& packet) {
        
        packet[0] = 0x1F;
        unsigned long long sign_len = 0;
        std::array<uint8_t, CIF_BYTES + 1>raw_pack;
        std::copy(cif_bytes.begin(), cif_bytes.end(), raw_pack.begin());
        raw_pack[CIF_BYTES] = '!';
        if (crypto_sign(packet.data() + 1, &sign_len, raw_pack.data(), 
            raw_pack.size(), client_sign_sk.data()) != 0) 
            return false;
        return true;
    }

    static void thread_run_core (window_mgr& w, const int fd, msg_buffer& buff, 
        client_session& s, const curr_user& u, lmsg_send_pool& lm_s,
        lmsg_recv_pool& lm_r, const client_server_pk_mgr& server_pk, 
        const key_mgr_25519& client_k, std::vector<std::string>& msg_vec, 
        int& core_err) {
              
        core_err = C_NORMAL_RETURN;
        if (fd < 0) {
            core_err = C_SOCK_FD_INVALID;
            return;
        }
        bool is_msg_recved = false;
        struct sockaddr_in src_addr;
        auto addr_len = sizeof(src_addr);
        size_t offset = 0;
        unsigned long long unsign_len = 0, aes_dec_len = 0;
        auto raw_beg = buff.recv_raw_buffer.data();
        auto aes_beg = buff.recv_aes_buffer.data();
        auto sid = s.get_server_sid();
        auto cif = s.get_cinfo_hash_bytes();
        
        std::array<uint8_t, crypto_aead_aes256gcm_NPUBBYTES> aes_nonce;
        std::array<uint8_t, SID_BYTES> recved_sid;
        std::array<uint8_t, CIF_BYTES> recved_cif;
        std::array<uint8_t, HEARTBEAT_BYTES> hb_pack;
        std::array<uint8_t, GOODBYE_BYTES> gby_pack;

        w.welcome_user(u.get_uemail(), u.get_uname());

        while (core_running) {
            if (heartbeat_timeout) {
                w.wprint_to_output(heartbeat_timeout_msg);
                core_err = C_HEARTBEAT_TIME_OUT;
                return;
            }
            if (send_gby_req) {
                w.wprint_to_output(client_exit_msg);
                if (!pack_goodbye(s.get_cinfo_hash_bytes(), 
                    client_k.get_sign_sk(), gby_pack)) {
                    core_err = C_GOODBYE_SENT_ERR;
                    return;
                }
                if (simple_send_stc(fd, s, gby_pack.data(), 
                    gby_pack.size()) < 0) {
                    core_err = C_HEARTBEAT_SENT_ERR;
                    return;
                }
                w.wprint_to_output(signed_out_msg);
                send_gby_req.store(false);
                return;
            }
            // Check the long message receivers / senders.
            auto now = lc_utils::now_time();
            if (now - last_lmsg_check.load() >= LMSG_ALIVE_SECS) {
                lm_r.check_all(now);
                lm_s.check_all(now);
            }
            auto bytes = recvfrom(fd, buff.recv_raw_buffer.data(), 
                buff.recv_raw_buffer.size(), 0, 
                (struct sockaddr *)(&src_addr), (socklen_t *)&addr_len);
            errno = 0;
            is_msg_recved = false;
            if (bytes < 0) {
                // Handling sending workloads.
                if (!errno || errno == EWOULDBLOCK || errno == EAGAIN) {
                    if (send_msg_req) {
                        if (send_msg_body.size() > 0) {
                            mtx.lock();
                            simple_secure_send_stc(fd, 0x10, s, buff, 
                                reinterpret_cast<const uint8_t *>
                                    (send_msg_body.c_str()), 
                                send_msg_body.size());
                            mtx.unlock();
                        }
                        send_msg_req.store(false);
                        continue;
                    }
                    else {
                        if (heartbeat_req) {
                            if (!pack_heartbeat(s.get_cinfo_hash_bytes(),
                                client_k.get_sign_sk(), hb_pack)) {
                                core_err = C_HEARTBEAT_SENT_ERR;
                                return;
                            }
                            if (simple_send_stc(fd, s, hb_pack.data(), 
                                hb_pack.size()) < 0) {
                                core_err = C_HEARTBEAT_SENT_ERR;
                                return;
                            }
                            last_heartbeat_sent.store(lc_utils::now_time());
                            heartbeat_req.store(false);
                        }
                        continue;
                    }
                }
                core_err = C_SOCKET_RECV_ERR;
                return;
            }
            if (bytes < CLIENT_RECV_MIN_BYTES) 
                continue;
            offset = 0;
            auto header = buff.recv_raw_buffer[0];
            if (header != 0x11 && header != 0x10 && 
                header != 0x1F && header != 0x13)
                continue;
            if (header == 0x11 || header == 0x13) {
                ++ offset;
                if (crypto_sign_open(nullptr, &unsign_len, raw_beg + offset,
                    bytes - 1, server_pk.get_server_spk().data()) != 0)
                    continue;
                offset += crypto_sign_BYTES;
                // Handle the 0x11 (short messages with signature but not cif)
                if (header == 0x11) {
                    std::string msg_str(
                        reinterpret_cast<const char *>(raw_beg + offset), 
                        bytes - offset);
                    msg_vec.push_back(msg_str);
                    is_msg_recved = true;
                }
                // Handle the 0x13 (long messages with signature and cif)
                else {
                    if (bytes < 1 + CIF_BYTES + MSG_ID_BYTES + 2)
                        continue;
                    if (std::memcmp(raw_beg + offset, cif.data(), cif.size()) != 0)
                        continue;
                    offset += cif.size();
                    std::vector<uint8_t> chunk(bytes - offset);
                    std::copy(raw_beg + offset, raw_beg + bytes, chunk.begin());
                    auto msg_id = lmsg_receiver::get_chunk_msg_id(chunk);
                    auto msg_id_bytes = lc_utils::u64_to_bytes(msg_id);
                    lm_r.add_lmsg(chunk);
                    auto receiver = lm_r.get_receiver(msg_id);
                    if (!receiver) {
                        w.wprint_to_output(lmsg_recv_failed);
                        continue;
                    }
                    if (receiver->recv_timeout()) {
                        w.wprint_to_output(lmsg_recv_failed);
                        continue;
                    }
                    if (!receiver->recv_done()) {
                        if (!receiver->last_chunk_received())
                            continue;
                        
                        receiver->check_missing_chunks();
                        if (!receiver->recv_done()) {
                            auto missed = receiver->missing_chunks_to_bytes();
                            if (1 + crypto_sign_BYTES + CIF_BYTES + 
                                missed.size() > BUFF_BYTES)
                                continue;
                            // Send 0x14 message to report the missed chunks
                            simple_sign_send_stc(fd, 0x14, s, client_k, buff, 
                                reinterpret_cast<uint8_t *>(missed.data()), 
                                missed.size());
                            continue;
                        }
                    }
                    // Tell the server of receiving ok.
                    simple_sign_send_stc(fd, 0x14, s, client_k, buff, 
                                         msg_id_bytes.data(),
                                         msg_id_bytes.size());
                        
                    receiver->order_recv_chunks();
                    auto chunks = receiver->get_recv_chunks_ordered();
                    std::string recved_lmsg_body;
                    for (auto it : chunks) 
                        recved_lmsg_body += std::string(
                            reinterpret_cast<char *>(it.data()), it.size());
                    msg_vec.push_back(recved_lmsg_body);
                    // Delete this receiver.
                    lm_r.delete_receiver(msg_id);
                    is_msg_recved = true;
                }
            }
            else if (header == 0x1F) {
                if (bytes != HEARTBEAT_BYTES)
                    continue;
                ++ offset;
                if (crypto_sign_open(nullptr, &unsign_len, raw_beg + offset,
                    bytes - offset, server_pk.get_server_spk().data()) != 0)
                    continue;
                if (std::memcmp(raw_beg + 1 + crypto_sign_BYTES, cif.data(), 
                    cif.size()) != 0)
                    continue;
                mtx.lock();
                s.update_src_addr(src_addr);
                mtx.unlock();
                last_heartbeat_recv.store(lc_utils::now_time());
                continue;
            }
            else {
                ++ offset;
                std::copy(raw_beg + offset, 
                    raw_beg + offset + crypto_aead_aes256gcm_NPUBBYTES, 
                    aes_nonce.begin());
                offset += crypto_aead_aes256gcm_NPUBBYTES;
                auto res = 
                    (crypto_aead_aes256gcm_decrypt(
                        aes_beg, &aes_dec_len, NULL,
                        raw_beg + offset, bytes - offset,
                        NULL, 0,
                        aes_nonce.data(), s.get_aes256gcm_key().data()
                    ) == 0);
                buff.recv_aes_bytes = aes_dec_len;
                if (!res) 
                    continue;
                // Reading aes buffer.
                offset = 0;
                std::copy(aes_beg + offset, aes_beg + offset + SID_BYTES, 
                          recved_sid.begin());
                offset += SID_BYTES;
                std::copy(aes_beg + offset, aes_beg + offset + CIF_BYTES,
                          recved_cif.begin());
                offset += CIF_BYTES;
                if (sid != recved_sid || cif != recved_cif)
                    continue;
                auto msg_beg = aes_beg + offset;
                auto msg_len = aes_dec_len - offset;
                std::string msg_body(reinterpret_cast<char *>(msg_beg), msg_len);
                msg_vec.push_back(msg_body);
                is_msg_recved = true;
                if (msg_len == sizeof(s_signout) && 
                    std::memcmp(s_signout, msg_beg, sizeof(s_signout)) == 0) {
                    
                    w.wprint_to_output(auto_signout_msg);
                    auto_signout.store(true);
                    return;
                }
            }
            if (is_msg_recved) {
                w.fmt_prnt_msg(msg_vec.back(), u.get_uname());
            }
        }
    }

    // Close server and possible FD
    bool close_client (int err) {
        last_error = err;
        if (client_fd != -1) {
            close(client_fd); 
            client_fd = -1;
        }
        return err == 0;
    }

    int get_last_error (void) {
        return last_error;
    }
    
    bool start_client (void) {
        if (client_key.key_mgr_init() != 0) {
            std::cout << "Key manager not activated. @ START." << std::endl;
            return close_client(CLIENT_KEY_MGR_ERROR);
        }
        client_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (client_fd < 0) 
            return close_client(SOCK_FD_INVALID);
        std::cout << "lichat client started. Handshaking now ..." << std::endl;
        return true;
    }

    std::vector<uint8_t> assemble_user_info(const bool is_signup, 
        const bool is_login_uemail, const std::string& uemail, 
        const std::string& uname, const std::string& password) {

        size_t vec_size = 0, offset = 0;
        if (is_signup) {
            vec_size = 1 + 1 + uemail.size() + 1 + uname.size() + 
                       1 + password.size() + 1;
            std::vector<uint8_t> vec(vec_size, 0x00);
            offset += 2;
            vec.insert(vec.begin() + offset, uemail.begin(), uemail.end());
            offset += (uemail.size() + 1);
            vec.insert(vec.begin() + offset, uname.begin(), uname.end());
            offset += (uname.size() + 1);
            vec.insert(vec.begin() + offset, password.begin(), password.end());
            return vec;
        }   
        if (is_login_uemail) 
            vec_size = 1 + 1 + uemail.size() + 1 + password.size() + 1;
        else
            vec_size = 1 + 1 + uname.size() + 1 + password.size() + 1;
        std::vector<uint8_t> vec(vec_size);
        vec[0] = 0x01;
        if (is_login_uemail) {
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

    void print_menu (void) {
        std::cout << main_menu << std::endl;
    }

    int simple_send (const client_session& curr_s, 
        const uint8_t *buf, size_t n) {
        auto addr = curr_s.get_src_addr();
        return sendto(client_fd, buf, n, 0, 
                        (const struct sockaddr*)(&addr), sizeof(addr));
    }

    // Simplify the socket send function.
    // Format : 1-byte header + 
    //          cinfo_hash +
    //          aes_nonce + 
    //          aes_gcm_encrypted (sid + msg_body)
    int simple_secure_send (const uint8_t header, const client_session& curr_s, 
        const uint8_t *raw_msg, size_t raw_n) {
            
        if (curr_s.get_status() == 0 || curr_s.get_status() == 1) 
            return -1;
        
        bool raw_msg_empty = false;
        size_t raw_bytes = raw_n;

        if (raw_msg == nullptr || raw_n == 0) {
            raw_msg_empty = true;
            raw_bytes = 0;
        }

        if ((1 + CIF_BYTES + crypto_aead_aes256gcm_NPUBBYTES + SID_BYTES + 
            raw_bytes + crypto_aead_aes256gcm_ABYTES) > BUFF_BYTES) 
            return -3;

        auto aes_key = curr_s.get_aes256gcm_key();
        auto cif = curr_s.get_cinfo_hash();
        auto cif_bytes = lc_utils::u64_to_bytes(cif);
        auto sid = curr_s.get_server_sid();

        std::array<uint8_t, crypto_aead_aes256gcm_NPUBBYTES> client_aes_nonce;
        size_t offset = 0, aes_enc_len = 0;

        // Padding the first byte
        buffer.send_buffer[0] = header;
        ++ offset;
        
        // Padding the cinfo_hash
        std::copy(cif_bytes.begin(), cif_bytes.end(), 
                    buffer.send_buffer.begin() + offset);
        offset += cif_bytes.size();

        // Padding the aes_nonce
        lc_utils::generate_aes_nonce(client_aes_nonce);
        std::copy(client_aes_nonce.begin(), client_aes_nonce.end(), 
                    buffer.send_buffer.begin() + offset);
        offset += client_aes_nonce.size();

        // Construct the raw message: sid + cif + msg_body
        std::copy(sid.begin(), sid.end(), buffer.send_aes_buffer.begin());
        if (!raw_msg_empty) {
            std::copy(raw_msg, raw_msg + raw_bytes, 
                    buffer.send_aes_buffer.begin() + sid.size());
        }
        // Record the buffer occupied size.
        buffer.send_aes_bytes = sid.size() + raw_bytes;

        // AES encrypt and padding to the send_buffer.
        auto res = crypto_aead_aes256gcm_encrypt(
            buffer.send_buffer.data() + offset, 
            reinterpret_cast<unsigned long long *>(&aes_enc_len),
            reinterpret_cast<const uint8_t *>(buffer.send_aes_buffer.data()),
            buffer.send_aes_bytes, 
            NULL, 0, NULL, 
            client_aes_nonce.data(), aes_key.data()
        );
        buffer.send_bytes = offset + aes_enc_len;
        if (res != 0) 
            return -5;
        auto ret = simple_send(curr_s, buffer.send_buffer.data(), 
                                buffer.send_bytes);
        if (ret < 0) 
            return -7;
        return ret;
    }


    // Read the recv_raw_buffer and decrypt message body to recv_aes_buffer
    bool decrypt_recv_0x10raw_bytes (const ssize_t recved_raw_bytes) {
        if (recved_raw_bytes < lc_utils::calc_encrypted_len(1))
            return false;
        auto aes_key = session.get_aes256gcm_key();
        std::array<uint8_t, crypto_aead_aes256gcm_NPUBBYTES> aes_nonce;
        std::array<uint8_t, SID_BYTES> sid;
        std::array<uint8_t, CIF_BYTES> cif_bytes;
        auto begin = buffer.recv_raw_buffer.begin();
        size_t offset = 0; // Omit first byte 0x10.
        unsigned long long aes_dec_len = 0;
        auto header = buffer.recv_raw_buffer[0];
        if (header != 0x10) 
            return false;
        ++ offset;
        std::copy(begin + offset, 
                    begin + offset + crypto_aead_aes256gcm_NPUBBYTES, 
                    aes_nonce.begin());
        offset += crypto_aead_aes256gcm_NPUBBYTES;
        auto ret = 
            (crypto_aead_aes256gcm_decrypt(
                buffer.recv_aes_buffer.begin(), &aes_dec_len, NULL,
                begin + offset, recved_raw_bytes - offset,
                NULL, 0,
                aes_nonce.data(), aes_key.data()
            ) == 0);
        buffer.recv_aes_bytes = aes_dec_len;
        if (aes_dec_len <= SID_BYTES + CIF_BYTES)
            return false;
        return ret;
    }

    ssize_t wait_server_response (struct sockaddr_in& addr) {
        buffer.clear_buffer();
        struct sockaddr_in src_addr;
        auto addr_len = sizeof(src_addr);
        struct timeval tv;
        tv.tv_sec = HANDSHAKE_TIMEOUT_SECS;
        tv.tv_usec = 0;

        if (setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, 
            sizeof(tv)) < 0) {
            return -127;
        }

        auto ret = recvfrom(client_fd, buffer.recv_raw_buffer.data(), 
                            buffer.recv_raw_buffer.size(), 0, 
                            (struct sockaddr *)(&src_addr), 
                            (socklen_t *)&addr_len);
        addr = src_addr;
        return ret;
    }

    bool user_input (const std::string& prompt, 
        std::string& dest_str, size_t max_times, bool is_password,
        const std::function<int(const std::string&)>& fmt_check_func) {
        size_t retry = 0;
        bool fmt_correct = false;
        std::cout << prompt;
        while (retry < max_times) {
            if (is_password) 
                dest_str = lc_utils::getpass_stdin("");
            else 
                std::getline(std::cin, dest_str);
            ++ retry;
            if (fmt_check_func(dest_str) != 0) {
                std::cout << "Invalid format. Please retry (" 
                          << retry << '/' << max_times << ")." << std::endl;
            }
            else {
                fmt_correct = true;
                break;
            }  
        }
        if (retry == max_times && !fmt_correct) {
            std::cout << "Too many input failures. Abort." << std::endl;
            return false;
        }
        else {
            return true;
        }
    }

    bool sign_cid_cpk (std::array<uint8_t, crypto_sign_BYTES + CID_BYTES + 
        crypto_box_PUBLICKEYBYTES>& signed_cid_cpk) {

        if (!client_key.is_activated())
            return false;
        auto client_ssk = client_key.get_sign_sk();
        auto client_cid = session.get_client_cid();
        auto client_cpk = client_key.get_crypto_pk();
        std::array<uint8_t, CID_BYTES + crypto_box_PUBLICKEYBYTES> cid_cpk;
        unsigned long long signed_len;
        std::copy(client_cid.begin(), client_cid.end(), cid_cpk.begin());
        std::copy(client_cpk.begin(), client_cpk.end(), 
                    cid_cpk.begin() + client_cid.size());
        if (crypto_sign(signed_cid_cpk.data(), &signed_len, cid_cpk.data(), 
                    cid_cpk.size(), client_ssk.data()) != 0) 
            return false;
        return true;
    }
    
    bool run_client (void) {
        if (!client_key.is_activated()) {
            std::cout << "Key manager not activated." << std::endl;
            return close_client(CLIENT_KEY_MGR_ERROR);
        }
        if (client_fd == -1) {
            std::cout << "Client not started." << std::endl;
            return close_client(SOCK_FD_INVALID);
        }
        std::array<uint8_t, crypto_aead_aes256gcm_NPUBBYTES> server_aes_nonce;
        std::array<uint8_t, crypto_aead_aes256gcm_KEYBYTES> aes_key;
        //std::array<uint8_t, SID_BYTES> server_sid;
        std::array<uint8_t, CIF_BYTES> recved_cif_bytes;
        std::array<uint8_t, SID_BYTES> recved_server_sid;
        std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> recved_server_spk;
        std::array<uint8_t, crypto_box_PUBLICKEYBYTES> recved_server_cpk;
        struct sockaddr_in msg_addr;
        size_t aes_enc_len = 0;
        size_t aes_dec_len = 0;
        size_t offset = 0;

        while (true) {
            auto status = session.get_status(); 
            if (status == 0) {
                auto read_pk = server_pk_mgr.read_server_pk();
                offset = 0;
                if (!read_pk) 
                    buffer.send_buffer[0] = 0x00;
                else 
                    buffer.send_buffer[0] = 0x01;
                ++ offset;
                auto client_spk = client_key.get_sign_pk();
                std::copy(client_spk.begin(), client_spk.end(), 
                            buffer.send_buffer.begin() + offset);
                offset += client_spk.size();
                std::array<uint8_t, 
                    crypto_sign_BYTES + CID_BYTES + crypto_box_PUBLICKEYBYTES> 
                    signed_cid_cpk;

                if (!sign_cid_cpk(signed_cid_cpk)) 
                    return close_client(MSG_SIGNING_FAILED);

                std::copy(signed_cid_cpk.begin(), signed_cid_cpk.end(), 
                            buffer.send_buffer.begin() + offset);
                buffer.send_bytes = offset + signed_cid_cpk.size();
                simple_send(session, buffer.send_buffer.data(), 
                            buffer.send_bytes);

                // 0x00: requested server key, 0x01: not requested server key
                session.sent_cinfo((buffer.send_buffer[0] == 0x00));
                continue;
            }
            if (status == 1 || status == 2 || status == 4) {
                // Here the socket is blocking mode for reliability.
                auto wait_res = wait_server_response(msg_addr);
                if (wait_res == -127) {
                    std::cout << "Failed to set socket option." << std::endl;
                    return close_client(SOCK_SETOPT_FAILED);
                }
                else if (wait_res < 0) {
                    std::cout << "Handshaking timeout (" 
                        << HANDSHAKE_TIMEOUT_SECS << " secs)." << std::endl;
                    return close_client(HANDSHAKE_TIMEOUT);
                }
                buffer.recv_raw_bytes = wait_res;
                if (buffer.recved_insuff_bytes(CLIENT_RECV_MIN_BYTES) || 
                    buffer.recved_overflow()) 
                    continue; // If size is invalid, ommit.
                if (status == 1) {
                    offset = 0;
                    auto header = buffer.recv_raw_buffer[0];
                    auto beg = buffer.recv_raw_buffer.begin();
                    ++ offset;
                    if ((buffer.recv_raw_bytes == sizeof(server_ff_failed)) && 
                        (std::memcmp(beg, server_ff_failed, 
                        sizeof(server_ff_failed)) == 0)) {
                        session.reset();
                        continue;
                    }
                    if (header != 0x00 && header != 0x01)
                        continue;
                    unsigned long long unsign_len = 0;
                    if (header == 0x00) {
                        if (!session.requested_server_key())
                            continue;
                        size_t expected_len = 1 + crypto_sign_PUBLICKEYBYTES + 
                                              crypto_sign_BYTES + 
                                              crypto_box_PUBLICKEYBYTES +
                                              crypto_aead_aes256gcm_NPUBBYTES + 
                                              SID_BYTES + CIF_BYTES + 
                                              sizeof(ok) + 
                                              crypto_aead_aes256gcm_ABYTES;
                        if (buffer.recv_raw_bytes != expected_len)
                            continue;
                        std::copy(beg + offset, 
                                    beg + offset + crypto_sign_PUBLICKEYBYTES, 
                                    recved_server_spk.begin());
                        offset += recved_server_spk.size();
                        if (crypto_sign_open(nullptr, &unsign_len, beg + offset, 
                            crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES, 
                            recved_server_spk.data()) != 0) 
                            continue;
                        offset += crypto_sign_BYTES;
                        std::copy(beg + offset, 
                                beg + offset + crypto_box_PUBLICKEYBYTES, 
                                recved_server_cpk.begin());
                        offset += crypto_box_PUBLICKEYBYTES;
                        if (!server_pk_mgr.update_server_pk(recved_server_spk, 
                            recved_server_cpk))
                            return close_client(SERVER_PK_MGR_ERROR);
                    }
                    else {
                        if (session.requested_server_key())
                            continue;
                        size_t expected_len = 1 + crypto_sign_BYTES + 
                                              sizeof(ok) +
                                              crypto_aead_aes256gcm_NPUBBYTES + 
                                              SID_BYTES + CIF_BYTES + 
                                              sizeof(ok) + 
                                              crypto_aead_aes256gcm_ABYTES;
                        if (buffer.recv_raw_bytes != expected_len)
                            continue;
                        if (crypto_sign_open(nullptr, &unsign_len, beg + offset, 
                            crypto_sign_BYTES + sizeof(ok), 
                            server_pk_mgr.get_server_spk().data()) != 0) 
                            continue;
                        
                        offset += crypto_sign_BYTES + sizeof(ok);
                    }
                    std::copy(beg + offset, 
                                beg + offset + crypto_aead_aes256gcm_NPUBBYTES, 
                                server_aes_nonce.begin());

                    offset += crypto_aead_aes256gcm_NPUBBYTES;

                    if (lc_utils::calc_aes_key(aes_key, 
                            server_pk_mgr.get_server_cpk(), 
                            client_key.get_crypto_sk()) != 0)
                        continue;
                    
                    auto is_aes_ok = 
                        (crypto_aead_aes256gcm_decrypt(
                            buffer.recv_aes_buffer.begin(), 
                            reinterpret_cast<unsigned long long *>(&aes_dec_len),
                            NULL, beg + offset, 
                            SID_BYTES + CIF_BYTES + sizeof(ok) + 
                                crypto_aead_aes256gcm_ABYTES,
                            NULL, 0,
                            server_aes_nonce.data(), aes_key.data()
                        ) == 0);

                    buffer.recv_aes_bytes = aes_dec_len;
                    auto is_msg_ok = ((aes_dec_len == SID_BYTES + 
                        CIF_BYTES + sizeof(ok)) && 
                        (std::memcmp(buffer.recv_aes_buffer.begin() + 
                            SID_BYTES + CIF_BYTES, ok, sizeof(ok)) == 0));

                    auto aes_beg = buffer.recv_aes_buffer.begin();
                    if (is_aes_ok && is_msg_ok) {
                        session.update_src_addr(msg_addr);
                        std::copy(aes_beg, aes_beg + SID_BYTES, 
                                    recved_server_sid.begin());
                        std::copy(aes_beg + SID_BYTES, 
                                    aes_beg + SID_BYTES + CIF_BYTES, 
                                    recved_cif_bytes.begin());

                        auto ret = session.prepare(server_pk_mgr, client_key, 
                                        recved_server_sid, recved_cif_bytes);
                        if (ret == 0) {
                            simple_secure_send(0x02, session, ok, sizeof(ok));
                            std::cout << "Secure session prepared OK!\t" 
                                      << session.get_status() << std::endl;
                            continue;
                        }
                        else if (ret < 0) 
                            return close_client(SESSION_PREP_FAILED);
                        is_msg_ok = false;
                    }
                    offset = 0;
                    if (!is_aes_ok) {
                        buffer.send_buffer[0] = 0xEF;
                        std::copy(std::begin(client_ef_keyerr), 
                                    std::end(client_ef_keyerr), 
                                    buffer.send_buffer.begin() + 1);
                    }
                    else {
                        buffer.send_buffer[0] = 0xDF;
                        std::copy(std::begin(client_df_msgerr), 
                                    std::end(client_df_msgerr), 
                                    buffer.send_buffer.begin() + 1);
                    }
                    offset += (1 + ERR_CODE_BYTES);
                    auto client_spk = client_key.get_sign_pk();
                    std::copy(client_spk.begin(), client_spk.end(), 
                                buffer.send_buffer.begin() + offset);
                    offset += client_spk.size();
                    std::array<uint8_t, crypto_sign_BYTES + CID_BYTES + 
                                crypto_box_PUBLICKEYBYTES> signed_cid_cpk;
                    if (!sign_cid_cpk(signed_cid_cpk)) 
                        return close_client(MSG_SIGNING_FAILED);

                    std::copy(signed_cid_cpk.begin(), signed_cid_cpk.end(), 
                                buffer.send_buffer.begin() + offset);
                    buffer.send_bytes = offset + signed_cid_cpk.size();
                    simple_send(session, buffer.send_buffer.data(), 
                                buffer.send_bytes);
                    session.reset();
                    continue;
                }
                if (status == 2) {
                    offset = 0;
                    auto header = buffer.recv_raw_buffer[0];
                    auto beg = buffer.recv_raw_buffer.begin();
                    // 1 + 6-byte err + CIF + deleted_sid + server_sign_pk + signed(server_cpk)
                    size_t expected_err_size = 1 + ERR_CODE_BYTES + CIF_BYTES + 
                                               SID_BYTES + 
                                               crypto_sign_PUBLICKEYBYTES + 
                                               crypto_sign_BYTES + 
                                               crypto_box_PUBLICKEYBYTES;

                    if (buffer.recv_raw_bytes == expected_err_size) {
                        if (std::memcmp(beg, server_ef_keyerr, 
                            sizeof(server_ef_keyerr) == 0) || 
                            std::memcmp(beg, server_df_msgerr, 
                            sizeof(server_df_msgerr) == 0)) {

                            offset += 1 + ERR_CODE_BYTES;
                            std::copy(beg + offset, beg + offset + CIF_BYTES, 
                                        recved_cif_bytes.begin());

                            offset += CIF_BYTES;
                            std::copy(beg + offset, beg + offset + SID_BYTES, 
                                        recved_server_sid.begin());
                            offset += SID_BYTES;
                            if (recved_cif_bytes == 
                                session.get_cinfo_hash_bytes() && 
                                session.get_server_sid() == 
                                recved_server_sid) {
                                    
                                std::copy(beg + offset, 
                                    beg + offset + crypto_sign_PUBLICKEYBYTES, 
                                    recved_server_spk.begin());

                                offset += crypto_sign_PUBLICKEYBYTES + 
                                          crypto_sign_BYTES;
                                std::copy(beg + offset, 
                                    beg + offset + crypto_box_PUBLICKEYBYTES, 
                                    recved_server_cpk.begin());

                                server_pk_mgr.update_server_pk(
                                    recved_server_spk, recved_server_cpk);
                                session.reset();
                                continue;
                            }
                        }
                    }
                    offset = 0;
                    if (header != 0x02) 
                        continue; // Now, only handles 0x02 header.
                        // Expected: 0x02 + aes_nonce + encrypted(sid + cif + ok + checksum)
                    ++ offset;
                    size_t expected_ok_size = 1 + 
                                              crypto_aead_aes256gcm_NPUBBYTES + 
                                              SID_BYTES + CIF_BYTES + 
                                              sizeof(ok) + 
                                              crypto_aead_aes256gcm_ABYTES;

                    if (buffer.recv_raw_bytes != expected_ok_size)
                        continue; // Invalid message length.
                    std::copy(beg + offset, 
                        beg + offset + crypto_aead_aes256gcm_NPUBBYTES, 
                        server_aes_nonce.begin());

                    offset += crypto_aead_aes256gcm_NPUBBYTES;
                    auto is_aes_ok = 
                        (crypto_aead_aes256gcm_decrypt(
                            buffer.recv_aes_buffer.begin(), 
                            reinterpret_cast<unsigned long long *>(&aes_dec_len),
                            NULL, beg + offset, 
                            SID_BYTES + CIF_BYTES + sizeof(ok) + 
                                crypto_aead_aes256gcm_ABYTES,
                            NULL, 0,
                            server_aes_nonce.data(), 
                            session.get_aes256gcm_key().data()
                        ) == 0);
                    buffer.recv_aes_bytes = aes_dec_len;
                    if (!is_aes_ok)
                        continue; // Invalid key, probably not from the previous server.
                    if (std::memcmp(buffer.recv_aes_buffer.begin() + 
                        SID_BYTES + CIF_BYTES, ok, sizeof(ok)) != 0)
                        continue; // Not expected message ok.

                    session.update_src_addr(msg_addr);
                    session.activate(); // status already is confirmed as 2, so activate would always be true.
                    std::cout << "Secure session activated OK!\t" 
                              << session.get_status() << std::endl;
                    continue; 
                }
                // Now status == 4
                if (buffer.recv_raw_bytes < lc_utils::calc_encrypted_len(1) || 
                    buffer.recv_raw_bytes > 
                        lc_utils::calc_encrypted_len(UNAME_MAX_BYTES))
                    continue;
                if (buffer.recv_raw_buffer[0] != 0x10)
                    continue;
                if (!decrypt_recv_0x10raw_bytes(buffer.recv_raw_bytes))
                    continue;
                auto aes_beg = buffer.recv_aes_buffer.begin();
                std::copy(aes_beg, aes_beg + SID_BYTES, 
                            recved_server_sid.begin());
                std::copy(aes_beg + SID_BYTES, aes_beg + SID_BYTES + CIF_BYTES, 
                            recved_cif_bytes.begin());
                if (recved_cif_bytes != session.get_cinfo_hash_bytes() || 
                    recved_server_sid != session.get_server_sid())
                    continue;
                auto msg_body = aes_beg + SID_BYTES + CIF_BYTES;
                auto msg_size = buffer.recv_aes_bytes - SID_BYTES - CIF_BYTES;
                if (msg_size < 1 || msg_size > UNAME_MAX_BYTES)
                    continue;
                if (msg_size == 1) {
                    std::cout << "Auth failed and rejected by the server." 
                              << std::endl;
                    std::cout << parse_server_auth_error(*msg_body) 
                              << std::endl;
                    session.set_status(3);
                    continue;
                }
                auto uinfo_res = lc_utils::split_buffer(
                    msg_body + 1, msg_size - 1, msg_body[0], 3
                );
                if (uinfo_res.size() != 2)
                    continue;
                std::cout << "Auth succeeded by the server." << std::endl;
                session.auth_ok();
                user.set_suffix_flag(msg_body[0] == '!');
                user.set_uemail(uinfo_res[0]);
                user.set_uname(uinfo_res[1]);

                // Save the current time.
                auto now = lc_utils::now_time();
                last_heartbeat_sent.store(now);
                last_heartbeat_recv.store(now);
                break; // Auth succeeded
            }
            if (status == 3) {
                std::string option, login_type, uemail, uname, password;
                if (!user_input(main_menu, option, CLIENT_INPUT_RETRY, false,
                    [](const std::string& op) {
                    if (op == "1" || op == "2" || op == "signup" || 
                        op == "signin") return 0;
                    return 1;
                })) continue;
                if (option == "1" || option == "signup") { // Signing up, require email, username & password
                    if (!user_input(input_email, uemail, CLIENT_INPUT_RETRY, 
                        false, lc_utils::email_fmt_check))  
                        continue;

                    if (!user_input(input_username, uname, CLIENT_INPUT_RETRY, 
                        false, lc_utils::user_name_fmt_check)) 
                        continue;

                    if (!user_input(input_password, password, 
                        CLIENT_INPUT_RETRY, true, lc_utils::pass_fmt_check))
                        continue;
                    
                    std::string re = lc_utils::getpass_stdin(retype_password);
                    if (re != password) {
                        std::cout << "Failed to confirm your password.\n";
                        password.clear();
                        re.clear();
                        continue;
                    }
                }
                else {
                    if (!user_input(choose_login, login_type, 
                        CLIENT_INPUT_RETRY, false, [](const std::string& op) {
                        if (op == "1" || op == "2" || op == "email" || 
                            op == "username") return 0;
                        return 1;
                    })) continue;

                    if (login_type == "1" || login_type == "email") {
                        if (!user_input(input_email, uemail, CLIENT_INPUT_RETRY,
                            false, lc_utils::email_fmt_check))
                            continue;
                    }
                    else {
                        if (!user_input(input_username, uname, 
                            CLIENT_INPUT_RETRY, false, 
                            lc_utils::user_name_fmt_check))
                            continue;
                    }
                    if (!user_input(input_password, password, 
                        CLIENT_INPUT_RETRY, true, lc_utils::pass_fmt_check))
                        continue;
                }
                std::array<char, crypto_pwhash_STRBYTES> hashed_pwd;
                if (!lc_utils::pass_hash_dryrun(password, hashed_pwd)) {
                    last_error = HASH_PASSWORD_FAILED;
                    password.clear(); // For security concern.
                    return close_client(HASH_PASSWORD_FAILED);
                }
                auto user_info = assemble_user_info(
                    (option == "1" || option == "signup"), 
                    (login_type == "1" || login_type == "email"),
                    uemail, uname, password);
                simple_secure_send(0x10, session, user_info.data(), 
                                    user_info.size());
                
                session.sent_auth();
                continue;
            }
        }

        if (!nonblock_socket()) 
            return close_client(UNBLOCK_SOCK_FAILED);

        send_msg_req.store(false);
        send_gby_req.store(false);
        core_running.store(true);
        heartbeating.store(true);
        auto_signout.store(false);
        heartbeat_timeout.store(false);
        last_lmsg_check.store(lc_utils::now_time());

        auto ret = winmgr.init();
        if (ret != W_NORMAL_RETURN) {
            std::cout << winmgr.error_to_string(ret) << std::endl;
            return close_client(WINDOW_MGR_ERROR);
        }
        winmgr.set();
        // Start the heartbeat thread.
        std::thread heartbeat(thread_heartbeat);
        // Start the core thread.
        int core_err = 0;
        std::thread core(std::bind(thread_run_core, winmgr, client_fd, buffer, 
            session, user, lmsg_sends, lmsg_recvs, server_pk_mgr, client_key, 
            messages, core_err));
        
        auto input_ret = winmgr.winput();
        if (heartbeat_timeout) 
            core_err = C_HEARTBEAT_TIME_OUT;
        // Stop the threads.
        heartbeating.store(false);
        core_running.store(false);
        // They should be joinable.
        core.join();
        heartbeat.join();

        // Clear ncurses resources.
        winmgr.force_close();

        // Print thread errors.
        if (auto_signout)
            std::cout << signout_close << std::endl;
        std::cout << parse_core_err(core_err) << std::endl;
        if (core_err == C_NORMAL_RETURN)
            return true;
        return close_client(CORE_ERROR);
    }
};

int main (int argc, char **argv) {
    lichat_client new_client;
    if (sodium_init() < 0) {
        std::cout << "Failed to init libsodium." << std::endl;
        return 1;
    }
    if (argc >= 3) {
        std::string addr_str(argv[1]);
        std::string port_str(argv[2]);
        std::cout << "Trying to connect to server " << addr_str << ":" 
                  << port_str << std::endl;
        if (!new_client.set_server_addr(addr_str, port_str)) {
            std::cout << "Warning: Failed to connect to server " << addr_str 
                      << ":" << port_str << std::endl;
            std::cout << "Warning: Will use the default server localhost:8081." 
                      << std::endl;
        }
        else {
            std::cout << "Will connect to the provided server " << addr_str 
                      << ":" << port_str << std::endl;
        }
    }
    else {
        std::cout << "Will use the default server localhost:8081." << std::endl;
    }
    
    if (!new_client.start_client()) {
        std::cout << "Failed to start client. Error Code: " 
                  << new_client.get_last_error() << std::endl;
        return 3;
    }
    if (!new_client.run_client()) {
        std::cout << "Client running failure. Error Code: " 
                  << new_client.get_last_error() << std::endl;
    }
    return new_client.get_last_error();
}