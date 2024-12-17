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
#include <thread>
#include <functional>
#include <fcntl.h>
#include <errno.h>
#include <mutex>

constexpr char welcome[] = "\nWelcome to LightChat Service (aka LiChat)!\n\
We support Free Software and Free Speech.\n\
Code: https://github.com/zhenrong-wang/lichat\n";

constexpr char prompt[] = "Enter your input: ";

std::atomic<bool> tui_running(false);
std::atomic<bool> send_msg_req(false);
std::atomic<time_t> last_heatbeat(0);

std::string send_msg_body;
std::mutex mtx;

enum client_errors {
    NORMAL_RETURN = 0,
    CLIENT_KEY_MGR_ERROR,
    SOCK_FD_INVALID,
    MSG_SIGNING_FAILED,
    SERVER_PK_MGR_ERROR,
    SESSION_PREP_FAILED,
    UNBLOCK_SOCK_FAILED,
    WINDOW_SIZE_INVALID,
    WINDOW_CREATION_FAILED,
    TUI_CORE_ERROR,
    HASH_PASSWORD_FAILED,
};

struct input_buffer {
    std::array<char, INPUT_BUFF_SIZE> ibuf;
    size_t bytes;
    
    input_buffer () : bytes(0) {}
    void clear () {
        std::memset (ibuf.data(), 0, bytes);
        bytes = 0;
    }
};

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
    input_buffer input;
    std::vector<std::string> messages;
    curr_user user;
    int last_error;

public:

    lichat_client () : 
        client_fd(-1), server_pk_mgr(client_server_pk_mgr()), 
        key_dir(default_key_dir), session(client_session()), 
        client_key(key_mgr_25519(key_dir, "client_")), buffer(msg_buffer()), 
        input(input_buffer()), user(curr_user()), last_error(0) {

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

    std::string parse_thread_err (const int& thread_err) {
        if (thread_err == 0) 
            return "Thread exit normally / gracefully.";
        else if (thread_err == -1)
            return "Some of the windows are null.";
        else if (thread_err == 1)
            return "The provided socket fd is invalid";
        else if (thread_err == 3)
            return "Failed to sign and/or send heartbeat.";
        else if (thread_err == 5)
            return "Socket communication error.";
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

    static void wprint_array(WINDOW *win, const uint8_t *arr, const size_t n) {
        wprintw(win, "\n");
        for (size_t i = 0; i < n; ++ i) 
            wprintw(win, "%x ", arr[i]);
        wprintw(win, "\n");
        wrefresh(win);
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
        const uint8_t *raw_msg, size_t raw_n) {
            
        if (curr_s.get_status() == 0 || curr_s.get_status() == 1) 
            return -1;

        if ((1 + CIF_BYTES + crypto_aead_aes256gcm_NPUBBYTES + SID_BYTES + 
            raw_n + crypto_aead_aes256gcm_ABYTES) > BUFF_SIZE) 
            return -3;

        auto aes_key = curr_s.get_aes256gcm_key();
        auto cif = curr_s.get_cinfo_hash();
        auto cif_bytes = lc_utils::u64_to_bytes(cif);
        auto sid = curr_s.get_server_sid();

        std::array<uint8_t, crypto_aead_aes256gcm_NPUBBYTES> client_aes_nonce;
        size_t offset = 0, aes_encrypted_len = 0;

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

        if ((offset + sid.size() + raw_n + crypto_aead_aes256gcm_ABYTES) > 
            BUFF_SIZE) {
            buff.send_bytes = offset;
            return -3; // buffer overflow occur.
        }

        // Construct the raw message: sid + cif + msg_body
        std::copy(sid.begin(), sid.end(), buff.send_aes_buffer.begin());
        std::copy(raw_msg, raw_msg + raw_n, 
                    buff.send_aes_buffer.begin() + sid.size());
        // Record the buffer occupied size.
        buff.send_aes_bytes = sid.size() + raw_n;

        // AES encrypt and padding to the send_buffer.
        auto res = crypto_aead_aes256gcm_encrypt(
            buff.send_buffer.data() + offset, 
            (unsigned long long *)&aes_encrypted_len,
            (const uint8_t *)buff.send_aes_buffer.data(),
            buff.send_aes_bytes, 
            NULL, 0, NULL, 
            client_aes_nonce.data(), aes_key.data()
        );
        buff.send_bytes = offset + aes_encrypted_len;
        if (res != 0) 
            return -5;
        auto ret = simple_send_stc(fd, curr_s, buff.send_buffer.data(), 
                                   buff.send_bytes);
        if (ret < 0) 
            return -7;
        return ret;
    }

    static bool need_heartbeat () {
        auto now = std::chrono::system_clock::now();
        auto now_time_t = std::chrono::system_clock::to_time_t(now);
        return ((now_time_t % CLIENT_HEARTBEAT_INVERTAL == 0) || 
                ((now_time_t - last_heatbeat) > CLIENT_HEARTBEAT_INVERTAL));
    }


    // Sign the "ok" and return.
    static bool pack_heatbeat (
        const std::array<uint8_t, CIF_BYTES>& cif_bytes,
        const std::array<uint8_t, crypto_sign_SECRETKEYBYTES>& client_sign_sk,
        std::array<uint8_t, HEATBEAT_BYTES>& packet) {
        
        packet[0] = 0x1F;
        size_t offset = 1;
        auto beg = packet.begin();
        std::copy(cif_bytes.begin(), cif_bytes.end(), beg + offset);
        offset += CIF_BYTES;
        unsigned long long sign_len = 0;
        if (crypto_sign(packet.data() + offset, &sign_len, ok, sizeof(ok), 
            client_sign_sk.data()) != 0) 
            return false;
        return true;
    }

    static void thread_run_core (WINDOW *top_win, WINDOW *side_win, 
        const int fd, msg_buffer& buff, const client_session& s, 
        const client_server_pk_mgr& server_pk, const curr_user& u,
        const key_mgr_25519& client_k, std::vector<std::string>& msg_vec, 
        int& thread_err) {
        
        thread_err = 0;
        if (top_win == nullptr || side_win == nullptr) {
            thread_err = -1;
            return;
        }
        if (fd < 0) {
            thread_err = 1;
            return;
        }
        bool is_msg_recved = false;
        struct sockaddr_in src_addr;
        auto addr_len = sizeof(src_addr);
        size_t offset = 0;
        unsigned long long unsign_len = 0, aes_decrypted_len = 0;
        auto raw_beg = buff.recv_raw_buffer.begin();
        auto aes_beg = buff.recv_aes_buffer.begin();
        auto sid = s.get_server_sid();
        auto cif = s.get_cinfo_hash_bytes();
        std::array<uint8_t, HEATBEAT_BYTES> hb_pack;

        wprintw(top_win, "\n[SYSTEM] Your unique email: %s\n", 
                u.get_uemail().c_str());     
        wprintw(top_win, "[SYSTEM] Your unique username: %s\n\n", 
                u.get_uname().c_str()); 
        wrefresh(top_win);

        while (tui_running) {
            auto bytes = recvfrom(fd, buff.recv_raw_buffer.data(), 
                buff.recv_raw_buffer.size(), MSG_WAITALL, 
                (struct sockaddr *)(&src_addr), (socklen_t *)&addr_len);
            errno = 0;
            is_msg_recved = false;
            if (bytes < 0) {
                // Handling sending workloads.
                if (!errno || errno == EWOULDBLOCK || errno == EAGAIN) {
                    if (send_msg_req && send_msg_body.size() > 0) {
                        mtx.lock();
                        simple_secure_send_stc(fd, 0x10, s, buff, 
                            (const uint8_t *)send_msg_body.c_str(), 
                            send_msg_body.size());
                        mtx.unlock();
                    }
                    if(send_msg_req) 
                        send_msg_req.store(false);
                    if (need_heartbeat) {
                        if (!pack_heatbeat(s.get_cinfo_hash_bytes(),
                            client_k.get_sign_sk(), hb_pack)) {
                            thread_err = 3;
                            return;
                        }
                        if (simple_send_stc(fd, s, hb_pack.data(), 
                            hb_pack.size()) != 0) {
                            thread_err = 3;
                            return;
                        }
                        last_heatbeat.store(lc_utils::now_time());
                    }
                    continue;
                }
                thread_err = 5;
                return;
            }
            if (bytes < CLIENT_RECV_MIN_BYTES) 
                continue;
            offset = 0;
            auto header = buff.recv_raw_buffer[0];
            if (header != 0x11 && header != 0x10)
                continue;
            if (header == 0x11) {
                ++ offset;
                if (crypto_sign_open(nullptr, &unsign_len, raw_beg + offset,
                    bytes - 1, server_pk.get_server_spk().data()) != 0)
                    continue;
                offset += crypto_sign_BYTES;
                std::string msg_str((const char *)(raw_beg + offset), 
                                    bytes - offset);
                msg_vec.push_back(msg_str);
                is_msg_recved = true;
            }
            else {
                std::array<uint8_t, crypto_aead_aes256gcm_NPUBBYTES> aes_nonce;
                std::array<uint8_t, SID_BYTES> recved_sid;
                std::array<uint8_t, CIF_BYTES> recved_cif;
                ++ offset;
                std::copy(raw_beg + offset, 
                    raw_beg + offset + crypto_aead_aes256gcm_NPUBBYTES, 
                    aes_nonce.begin());
                offset += crypto_aead_aes256gcm_NPUBBYTES;
                auto res = 
                    (crypto_aead_aes256gcm_decrypt(
                        aes_beg, &aes_decrypted_len, NULL,
                        raw_beg + offset, bytes - offset,
                        NULL, 0,
                        aes_nonce.data(), s.get_aes256gcm_key().data()
                    ) == 0);
                buff.recv_aes_bytes = aes_decrypted_len;
                if (!res) 
                    continue;
                offset = 0;
                std::copy(aes_beg + offset, aes_beg + offset + SID_BYTES, 
                            recved_sid.begin());
                offset += SID_BYTES;
                std::copy(aes_beg + offset, aes_beg + offset + CIF_BYTES,
                            recved_cif.begin());
                if (sid != recved_sid || cif != recved_cif)
                    continue;
                std::string msg_body((char *)(aes_beg + SID_BYTES + CIF_BYTES), 
                    buff.recv_aes_bytes - SID_BYTES - CIF_BYTES);
                msg_vec.push_back(msg_body);
                is_msg_recved = true;
            }
            if (is_msg_recved) 
                fmt_prnt_msg(top_win, msg_vec.back(), u.get_uname());
        }
    }

    // Every RAW message must start with at least:
    // timestamp,uname(or system), msg_body
    // Currenty this only handles narrow chars, not wide chars.

    static int fmt_for_print (std::string& out, const std::string& in, 
        const int col_start, const int col_end, const int win_width,
        const bool left_align) {
        if (in.empty())
            return -1;
        if (win_width <= 2 || col_start < 0 || col_end <= 0)
            return 1;
        if (col_end <= col_start || col_start >= win_width || col_end == 0)
            return 1;
        size_t line_len = static_cast<size_t>(col_end - col_start);
        size_t prefix_len = static_cast<size_t>(col_start); // Should be non-negative.
        size_t suffix_len = static_cast<size_t>(win_width - col_end); // Should be non-negative.
        std::string prefix(prefix_len, ' ');
        std::string suffix(suffix_len, ' ');

        // Handle single line input.
        if (in.size() <= line_len) {
            std::string padding(line_len - in.size(), ' ');
            if (left_align)
                out = prefix + in + padding + suffix;
            else 
                out = prefix + padding + in + suffix;
            return 0;
        }
        
        // Handle multiple line input.
        // All lines would be left aligned.
        size_t lines = ((in.size() % line_len) == 0) ? (in.size() / line_len)
                       : (in.size() / line_len + 1);
        out.clear();
        size_t pos = 0;
        for (size_t i = 0; i < lines - 1; ++ i) {
            out += (prefix + in.substr(pos, line_len) + suffix);
            pos += line_len;
        }
        std::string padding((line_len - in.size() % line_len), ' ');
        out += prefix + in.substr(pos) + padding + suffix;
        return 0;
    }

    static int fmt_prnt_msg (WINDOW *win, const std::string& raw_msg,
        const std::string& uname) {

        if (win == nullptr)
            return -1;
        if (raw_msg.size() == 0)
            return 1;
        auto parsed_msg = lc_utils::split_buffer((uint8_t *)raw_msg.data(), 
                          raw_msg.size(), ',', 3);
        if (parsed_msg.size() < 3)
            return 3; // Not a valid message
        //wprintw(win, "%s\n", raw_msg.c_str());
        //wrefresh(win);
        
        std::string timestmp = parsed_msg[0];
        std::string msg_uname = parsed_msg[1];
        std::string bare_msg = raw_msg.substr(parsed_msg[0].size() + 1 + 
                                              parsed_msg[1].size() + 1);
        
        if (bare_msg.empty())
            return 5;

        int height = 0, width = 0, pos = 0;

        // Important: before running the tui, we have checked the width is >=
        // min_width, which is 48. So the top_win width should be at least 32.
        // So the self_col_start >= 16; other_col_end >= 24.
        // So the construction of std::string(size, char) should work because
        // the provided size are positive. Although without strict check.
        getmaxyx(win, height, width);
        int col_start, col_end;
        std::string fmt_name, fmt_timestmp, fmt_msg;
        bool left_align = true;

        if (msg_uname == uname) {
            col_start = (width < 2) ? 0 : (width / 2); // value >= 0
            col_end = width;
            left_align = false;
            fmt_for_print(fmt_name, std::string("You:"), col_start, col_end, 
                          width, left_align);
        }
        else {
            col_start = 0;
            col_end = (width * 3 / 4);
            fmt_for_print(fmt_name, msg_uname, col_start, col_end, width, 
                          left_align);
        }
        fmt_for_print(fmt_timestmp, timestmp, col_start, col_end, width, 
                      left_align);
        fmt_for_print(fmt_msg, bare_msg, col_start, col_end, width, left_align);

        std::string fmt_lines = fmt_name + fmt_timestmp + fmt_msg;
        wprintw(win, "\n%s\n", fmt_lines.c_str());
        wrefresh(win);
        return 0;
    }

    // Refresh the input window
    bool refresh_input_win (WINDOW *win, const char& ch) {
        if (win == nullptr)
            return false;
        wprintw(win, "%c", ch);
        wrefresh(win);
        return true;
    }

    bool reset_input_win (WINDOW *win, const char *prompt) {
        if (win == nullptr)
            return false;
        wclear(win);
        if (prompt)
            wprintw(win, prompt);
        wrefresh(win);
        return true;
    }

    bool refresh_input_win (WINDOW *win, const char *prompt, 
        const input_buffer& input) {

        if(win == nullptr)
            return false;
        wclear(win);
        if(prompt)
            wprintw(win, prompt);
        wprintw(win, input.ibuf.data());
        wrefresh(win);
        return true;
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
        std::cout << "lichat client started." << std::endl;
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

        if ((1 + CIF_BYTES + crypto_aead_aes256gcm_NPUBBYTES + SID_BYTES + 
            raw_n + crypto_aead_aes256gcm_ABYTES) > BUFF_SIZE) 
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
        std::copy(cif_bytes.begin(), cif_bytes.end(), 
                    buffer.send_buffer.begin() + offset);
        offset += cif_bytes.size();

        // Padding the aes_nonce
        lc_utils::generate_aes_nonce(client_aes_nonce);
        std::copy(client_aes_nonce.begin(), client_aes_nonce.end(), 
                    buffer.send_buffer.begin() + offset);
        offset += client_aes_nonce.size();

        if ((offset + sid.size() + raw_n + crypto_aead_aes256gcm_ABYTES) > 
            BUFF_SIZE) {
            buffer.send_bytes = offset;
            return -3; // buffer overflow occur.
        }

        // Construct the raw message: sid + cif + msg_body
        std::copy(sid.begin(), sid.end(), buffer.send_aes_buffer.begin());
        std::copy(raw_msg, raw_msg + raw_n, 
                    buffer.send_aes_buffer.begin() + sid.size());
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
        unsigned long long aes_decrypted_len = 0;
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
                buffer.recv_aes_buffer.begin(), &aes_decrypted_len, NULL,
                begin + offset, recved_raw_bytes - offset,
                NULL, 0,
                aes_nonce.data(), aes_key.data()
            ) == 0);
        buffer.recv_aes_bytes = aes_decrypted_len;
        if (aes_decrypted_len <= SID_BYTES + CIF_BYTES)
            return false;
        return ret;
    }

    ssize_t wait_server_response (struct sockaddr_in& addr) {
        buffer.clear_buffer();
        struct sockaddr_in src_addr;
        auto addr_len = sizeof(src_addr);
        auto ret = recvfrom(client_fd, buffer.recv_raw_buffer.data(), 
                            buffer.recv_raw_buffer.size(), MSG_WAITALL, 
                            (struct sockaddr *)(&src_addr), 
                            (socklen_t *)&addr_len);
        addr = src_addr;
        return ret;
    }

    bool user_input (const std::string& prompt, 
        std::string& dest_str, size_t max_times, 
        const std::function<int(const std::string&)>& fmt_check_func) {
        size_t retry = 0;
        bool fmt_correct = false;
        std::cout << prompt;
        while (retry < max_times) {
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
        size_t aes_encrypted_len = 0;
        size_t aes_decrypted_len = 0;
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
                session.sent_cinfo((buffer.send_buffer[0] == 0x00)); // 0x00: requested server key, 0x01: not requested server key
                continue;
            }
            if (status == 1 || status == 2 || status == 4) {
                buffer.recv_raw_bytes = wait_server_response(msg_addr);
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
                            (unsigned long long *)(&aes_decrypted_len),
                            NULL,
                            beg + offset, 
                            SID_BYTES + CIF_BYTES + sizeof(ok) + 
                                crypto_aead_aes256gcm_ABYTES,
                            NULL, 0,
                            server_aes_nonce.data(), aes_key.data()
                        ) == 0);

                    buffer.recv_aes_bytes = aes_decrypted_len;
                    auto is_msg_ok = ((aes_decrypted_len == SID_BYTES + 
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
                            (unsigned long long *)(&aes_decrypted_len),
                            NULL,
                            beg + offset, 
                            SID_BYTES + CIF_BYTES + sizeof(ok) + 
                                crypto_aead_aes256gcm_ABYTES,
                            NULL, 0,
                            server_aes_nonce.data(), 
                            session.get_aes256gcm_key().data()
                        ) == 0);
                    buffer.recv_aes_bytes = aes_decrypted_len;
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
                break; // Auth succeeded
            }
            if (status == 3) {
                std::string option, login_type, uemail, uname, password;
                if (!user_input(main_menu, option, CLIENT_INPUT_RETRY, 
                    [](const std::string& op) {
                    if (op == "1" || op == "2" || op == "signup" || 
                        op == "signin") return 0;
                    return 1;
                })) continue;
                if (option == "1" || option == "signup") { // Signing up, require email, username & password
                    if (!user_input(input_email, uemail, CLIENT_INPUT_RETRY, 
                        lc_utils::email_fmt_check))  
                        continue;

                    if (!user_input(input_username, uname, CLIENT_INPUT_RETRY, 
                        lc_utils::user_name_fmt_check)) 
                        continue;

                    if (!user_input(input_password, password, 
                        CLIENT_INPUT_RETRY, lc_utils::pass_fmt_check))
                        continue;
                }
                else {
                    if (!user_input(choose_login, login_type, 
                        CLIENT_INPUT_RETRY, [](const std::string& op) {
                        if (op == "1" || op == "2" || op == "email" || 
                            op == "username") return 0;
                        return 1;
                    })) continue;

                    if (login_type == "1" || login_type == "email") {
                        if (!user_input(input_email, uemail, CLIENT_INPUT_RETRY,
                            lc_utils::email_fmt_check))
                            continue;
                    }
                    else {
                        if (!user_input(input_username, uname, 
                            CLIENT_INPUT_RETRY, lc_utils::user_name_fmt_check))
                            continue;
                    }
                    if (!user_input(input_password, password, 
                        CLIENT_INPUT_RETRY, lc_utils::pass_fmt_check))
                        continue;
                }
                std::array<char, crypto_pwhash_STRBYTES> hashed_pwd;
                if (!lc_utils::pass_hash_dryrun(password, hashed_pwd)) {
                    last_error = HASH_PASSWORD_FAILED;
                    password.clear(); // For security concern.
                    return false;
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

        //thread_run = true;
        if (!nonblock_socket()) 
            return close_client(UNBLOCK_SOCK_FAILED);

        // Now, the messaging interface started.
        setlocale(LC_ALL, "");
        initscr();
        cbreak();
        noecho();
        int height = 0, width = 0;
        getmaxyx(stdscr, height, width);

        if (width < WIN_WIDTH_MIN || height < WIN_HEIGHT_MIN) {
            std::cout << "Window size too small (min: w x h " 
                      << (int)WIN_WIDTH_MIN << " x " << (int)WIN_HEIGHT_MIN
                      << " )." << std::endl;
            endwin();
            return close_client(WINDOW_SIZE_INVALID);
        }

        WINDOW *top_win = newwin(height - BOTTOM_HEIGHT, 
                                width - SIDE_WIN_WIDTH, 0, 0);
        WINDOW *bottom_win = newwin(BOTTOM_HEIGHT, width - SIDE_WIN_WIDTH, 
                                height - BOTTOM_HEIGHT, 0);
        WINDOW *side_win = newwin(height, SIDE_WIN_WIDTH, 0, 
                                width - SIDE_WIN_WIDTH);

        if (!top_win || !bottom_win || !side_win) {
            std::cerr << "Failed to create windows." << std::endl;
            if (top_win) delwin(top_win);
            if (bottom_win) delwin(bottom_win);
            if (side_win) delwin(side_win);
            endwin();
            return close_client(WINDOW_CREATION_FAILED);
        }
        // activate keypad for input
        keypad(bottom_win, TRUE);
        // Activate scroll
        scrollok(top_win, TRUE);
        scrollok(bottom_win, TRUE);
        scrollok(side_win, TRUE);

        // Print welcome.
        wprintw(top_win, welcome);
        wrefresh(top_win);
        wprintw(bottom_win, prompt);
        wrefresh(bottom_win);
        wprintw(side_win, "Users: \n");
        wrefresh(side_win);

        tui_running.store(true);
        int thread_err = 0;
        std::thread tui(std::bind(thread_run_core, top_win, side_win, 
            client_fd, buffer, session, server_pk_mgr, user, client_key,
            messages, thread_err));

        while (true) {
            int ch = wgetch(bottom_win);
            if (ch == '\n' || input.bytes == input.ibuf.size() - 1) {
                if (input.bytes == 0) 
                    continue;
                if (input.bytes == 2 && 
                    std::strcmp(input.ibuf.data(), "q!") == 0) {
                    tui_running.store(false);
                    break;
                }
                mtx.lock();
                send_msg_body = std::string(input.ibuf.data(), input.bytes);
                mtx.unlock();
                send_msg_req.store(true);
                input.clear();
                refresh_input_win(bottom_win, prompt, input);
                continue;
            }
            if (ch != '\n' && (isprint(ch) || ch == '\t')) {
                input.ibuf[input.bytes] = ch;
                ++ input.bytes;
                refresh_input_win(bottom_win, ch);
                continue;
            }
            if (ch == KEY_BACKSPACE) {
                if (input.bytes > 0) {
                    -- input.bytes;
                    input.ibuf[input.bytes] = '\0';
                }
                refresh_input_win(bottom_win, prompt, input);
                continue;
            }
        }
        tui.join();
        delwin(top_win);
        delwin(bottom_win);
        delwin(side_win);
        endwin();
        std::cout << parse_thread_err(thread_err) << std::endl;
        if (thread_err == NORMAL_RETURN)
            return true;
        last_error = TUI_CORE_ERROR;
        return false;
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