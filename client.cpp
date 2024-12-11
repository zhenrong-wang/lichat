#include "lc_keymgr.hpp"
#include "lc_consts.hpp"
#include "lc_bufmgr.hpp"
#include "lc_sesmgr.hpp"

#include <iostream>
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

class client_server_pk_mgr {
    std::string server_pk_path;
    std::array<uint8_t, crypto_box_PUBLICKEYBYTES> server_public_key;
    bool status;

public:
    client_server_pk_mgr() : server_pk_path(client_side_server_pk), status(false) {}
    client_server_pk_mgr(std::string& path) : server_pk_path(path), status(false) {}

    bool read_server_pk(void) {
        std::vector<uint8_t> content;
        if(curve25519_key_mgr::read_curve25519_key_file(server_pk_path, content, crypto_box_PUBLICKEYBYTES) != 0)
            return false;
        if(content.size() != server_public_key.size())
            return false;
        std::copy(content.begin(), content.end(), server_public_key.begin());
        status = true;
        return true;
    }

    bool update_server_pk(const std::array<uint8_t, crypto_box_PUBLICKEYBYTES>& recved_key) {
        std::ofstream out_pk(server_pk_path, std::ios::binary);
        if(!out_pk.is_open())
            return false;
        out_pk.write(reinterpret_cast<const char *>(recved_key.data()), recved_key.size());
        out_pk.close();
        server_public_key = recved_key;
        status = true;
        return true;
    }

    void set_server_pk_path(const std::string& path) {
        server_pk_path = path;
    }

    const std::string& get_server_pk_path() const {
        return server_pk_path;
    }

    const std::array<uint8_t, crypto_box_PUBLICKEYBYTES>& get_server_pk() const {
        return server_public_key;
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
    uint64_t cinfo_hash; // Will be the unique key for unordered_map.
    
    struct sockaddr_in src_addr;   // the updated source_ddress. 
    //  0 - Empty: cid generated
    //  1 - Standby: client info sent, waiting for server response.
    //  2 - Prepared: server response received and good, sent ok waiting for server ok.
    //      cid + server_pk + aes256gcm_key + server_sid + cinfo_hash
    //  3 - Activated.
    int status; 
    bool is_server_key_req;

public:
    client_session() : status(0) {
        randombytes_buf(client_cid.data(), client_cid.size());
    }

    static int calc_aes_key(std::array<uint8_t, crypto_aead_aes256gcm_KEYBYTES>& aes_key, const std::array<uint8_t, crypto_box_PUBLICKEYBYTES>& pk, const std::array<uint8_t, crypto_box_SECRETKEYBYTES>& sk) {
        return crypto_box_beforenm(aes_key.data(), pk.data(), sk.data());
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

    int prepare(const client_server_pk_mgr& server_pk_mgr, const curve25519_key_mgr& client_key, const std::array<uint8_t, SID_BYTES>& sid, const std::array<uint8_t, CIF_BYTES>& cif) {
        if(status != 1)
            return -1;  // Not quite possible
        if(!server_pk_mgr.is_ready() || !client_key.is_activated()) 
            return -3;  // key_mgr not activated
        uint64_t cif_calc = session_item::hash_client_info(client_cid, client_key.get_public_key());

        uint64_t cif_calc2 = session_item::hash_client_info(client_cid, client_key.get_public_key());
        uint64_t cif_recv = session_item::bytes_to_u64(cif);
        if(cif_calc != cif_recv) 
            return 1;  //  Need to report to server, msg error
        if(crypto_box_beforenm(aes256gcm_key.data(), server_pk_mgr.get_server_pk().data(), client_key.get_secret_key().data()) != 0)
            return 3;  //  Need to report to server, msg error
        server_sid = sid;
        cinfo_hash = cif_recv;
        status = 2;
        return 0;      
    }
    
    bool activate() {
        if(status != 2) 
            return false;
        status = 3;
        return true;
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
    int client_fd;
    client_server_pk_mgr server_pk_mgr;
    std::pair<std::string, std::string> key_paths;
    client_session session;
    curve25519_key_mgr client_key;
    msg_buffer buffer;
    int last_error;

public:
    static bool string_to_u16(const std::string& str, uint16_t& res) {
        if(str.size() > 5)
            return false;
        for(auto c : str) {
            if(!isdigit(c))
                return false;
        }
        unsigned long n = std::stoul(str);
        if(n > std::numeric_limits<uint16_t>::max())
            return false;
        res = static_cast<uint16_t>(n);
        return true;
    }

    static bool get_addr_info(std::string& addr_str, std::array<char, INET_ADDRSTRLEN>& first_ipv4_addr) {
        if(addr_str.empty())
            return false;
        struct addrinfo hints, *res = nullptr;
        std::memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        std::memset(first_ipv4_addr.data(), 0, first_ipv4_addr.size());
        auto status = getaddrinfo(addr_str.c_str(), nullptr, &hints, &res);
        if(status != 0)
            return false;
        struct sockaddr_in *first = (sockaddr_in *)res->ai_addr;
        inet_ntop(AF_INET, &(first->sin_addr), first_ipv4_addr.data(), first_ipv4_addr.size());
        freeaddrinfo(res);
        return true;
    }

    lichat_client() : 
    client_fd(-1), server_pk_mgr(client_server_pk_mgr()), session(client_session()), client_key(curve25519_key_mgr()), buffer(msg_buffer()), last_error(0) {
        server_port = DEFAULT_SERVER_PORT;
        server_addr.sin_addr.s_addr = inet_addr(DEFAULT_SERVER_ADDR);
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(server_port);

        // Store the initial addr to session.
        session.update_src_addr(server_addr);
        key_paths = std::make_pair(default_client_pk, default_client_sk);
    }

    bool set_server_addr(std::string& addr_str, std::string& port_str) {
        std::array<char, INET_ADDRSTRLEN> ipv4_addr;
        uint16_t port_num;
        if(!get_addr_info(addr_str, ipv4_addr) || !string_to_u16(port_str, port_num)) 
            return false;
        server_port = port_num;
        server_addr.sin_addr.s_addr = inet_addr(ipv4_addr.data());
        server_addr.sin_port = htons(port_num);
        session.update_src_addr(server_addr);
        return true;
    }

    // Close server and possible FD
    bool close_client(int err) {
        last_error = err;
        if(client_fd != -1) {
            close(client_fd); 
            client_fd = -1;
        }
        return err == 0;
    }

    int get_last_error(void) {
        return last_error;
    }
    
    bool start_client(void) {
        if(client_key.key_mgr_init(key_paths.first, key_paths.second) != 0) {
            std::cout << "Key manager not activated." << std::endl;
            return close_client(1);
        }
        client_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if(client_fd < 0) 
            return close_client(3);
        std::cout << "lichat client started." << std::endl;
        return true;
    }

    int simple_send(const client_session& curr_s, const uint8_t *buf, size_t n) {
        auto addr = curr_s.get_src_addr();
        return sendto(client_fd, buf, n, 0, (const struct sockaddr*)(&addr), sizeof(addr));
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
        auto cif_bytes = session_item::u64_to_bytes(cif);
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
        session_item::generate_aes_nonce(client_aes_nonce);
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

    ssize_t wait_server_response(struct sockaddr_in& addr) {
        buffer.clear_buffer();
        auto src_addr = session.get_src_addr();
        auto addr_len = sizeof(src_addr);
        auto ret = recvfrom(client_fd, buffer.recv_raw_buffer.data(), buffer.recv_raw_buffer.size(), MSG_WAITALL, (struct sockaddr *)(&src_addr), (socklen_t *)&addr_len);
        addr = src_addr;
        return ret;
    }
    
    int run_client(void) {
        if(!client_key.is_activated()) {
            std::cout << "Key manager not activated." << std::endl;
            return 1;
        }
        if(client_fd == -1) {
            std::cout << "Client not started." << std::endl;
            return 3;
        }
        std::array<uint8_t, crypto_aead_aes256gcm_NPUBBYTES> server_aes_nonce;
        std::array<uint8_t, crypto_aead_aes256gcm_KEYBYTES> aes_key;
        std::array<uint8_t, crypto_box_PUBLICKEYBYTES> recved_server_pk;
        std::array<uint8_t, SID_BYTES> server_sid;
        std::array<uint8_t, CIF_BYTES> cinfo_hash_bytes;
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
                auto client_cid = session.get_client_cid();
                auto client_pk = client_key.get_public_key();
                std::copy(client_cid.begin(), client_cid.end(), buffer.send_buffer.begin() + offset);
                offset += client_cid.size();
                std::copy(client_pk.begin(), client_pk.end(), buffer.send_buffer.begin() + offset);
                buffer.send_bytes = offset + client_pk.size();
                simple_send(session, buffer.send_buffer.data(), buffer.send_bytes);
                session.sent_cinfo((buffer.send_buffer[0] == 0x00)); // 0x00: requested server key, 0x01: not requested server key
                continue;
            }
            if(status == 1 || status == 2) {
                buffer.recv_raw_bytes = wait_server_response(msg_addr);
                if(buffer.recved_insuff_bytes(CLIENT_RECV_MIN_BYTES) || buffer.recved_overflow()) 
                    continue; // If size is invalid, ommit.
                if(status == 1) {
                    offset = 0;
                    auto header = buffer.recv_raw_buffer[0];
                    auto begin = buffer.recv_raw_buffer.begin();
                    ++ offset;
                    if((buffer.recv_raw_bytes == sizeof(server_ff_failed)) && (std::memcmp(begin, server_ff_failed, sizeof(server_ff_failed)) == 0)) {
                        session.reset();
                        continue;
                    }
                    if(header != 0x00 && header != 0x01)
                        continue;
                    if(header == 0x00) {
                        if(!session.requested_server_key())
                            continue;
                        if(buffer.recv_raw_bytes != 1 + crypto_box_PUBLICKEYBYTES + crypto_aead_aes256gcm_NPUBBYTES + SID_BYTES + CIF_BYTES + sizeof(ok) + crypto_aead_aes256gcm_ABYTES)
                            continue;
                        std::copy(begin + offset, begin + offset + crypto_box_PUBLICKEYBYTES, recved_server_pk.begin());
                        offset += crypto_box_PUBLICKEYBYTES;
                        if(!server_pk_mgr.update_server_pk(recved_server_pk))
                            return 5;
                    }
                    else {
                        if(session.requested_server_key())
                            continue;
                        if(buffer.recv_raw_bytes != 1 + crypto_aead_aes256gcm_NPUBBYTES + SID_BYTES + CIF_BYTES + sizeof(ok) + crypto_aead_aes256gcm_ABYTES)
                            continue;
                    }
                    std::copy(begin + offset, begin + offset + crypto_aead_aes256gcm_NPUBBYTES, server_aes_nonce.begin());
                    offset += crypto_aead_aes256gcm_NPUBBYTES;
                    if(client_session::calc_aes_key(aes_key, server_pk_mgr.get_server_pk(), client_key.get_secret_key()) != 0) {
                        continue;
                    }
                    auto is_aes_ok = 
                        (crypto_aead_aes256gcm_decrypt(
                            buffer.recv_aes_buffer.begin(), (unsigned long long *)(&aes_decrypted_len),
                            NULL,
                            begin + offset, SID_BYTES + CIF_BYTES + sizeof(ok) + crypto_aead_aes256gcm_ABYTES,
                            NULL, 0,
                            server_aes_nonce.data(), aes_key.data()
                        ) == 0);

                    buffer.recv_aes_bytes = aes_decrypted_len;
                    auto is_msg_ok = ((aes_decrypted_len == SID_BYTES + CIF_BYTES + sizeof(ok)) && 
                    (std::memcmp(buffer.recv_aes_buffer.begin() + SID_BYTES + CIF_BYTES, ok, sizeof(ok)) == 0));

                    if(is_aes_ok && is_msg_ok) {
                        session.update_src_addr(msg_addr);
                        std::copy(buffer.recv_aes_buffer.begin(), buffer.recv_aes_buffer.begin() + SID_BYTES, server_sid.begin());
                        std::copy(buffer.recv_aes_buffer.begin() + SID_BYTES, buffer.recv_aes_buffer.begin() + SID_BYTES + CIF_BYTES, cinfo_hash_bytes.begin());
                        auto ret = session.prepare(server_pk_mgr, client_key, server_sid, cinfo_hash_bytes);
                        if(ret == 0) {
                            simple_secure_send(0x02, session, ok, sizeof(ok));
                            std::cout << "Secure session prepared OK!\t" << session.get_status() << std::endl;
                            continue;
                        }
                        else if(ret < 0) 
                            return 7;
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
                    auto client_cid = session.get_client_cid();
                    auto client_pk = client_key.get_public_key();
                    std::copy(client_cid.begin(), client_cid.end(), buffer.send_buffer.begin() + offset);
                    offset += client_cid.size();
                    std::copy(client_pk.begin(), client_pk.end(), buffer.send_buffer.begin() + offset);
                    buffer.send_bytes = offset + client_pk.size();
                    simple_send(session, buffer.send_buffer.data(), buffer.send_bytes);
                    session.reset();
                    continue;
                }
                // Now status == 2
                offset = 0;
                auto header = buffer.recv_raw_buffer[0];
                auto begin = buffer.recv_raw_buffer.begin();
                if(buffer.recv_raw_bytes == 1 + ERR_CODE_BYTES + CIF_BYTES + crypto_box_PUBLICKEYBYTES) {
                    if(std::memcmp(begin, server_ef_keyerr, sizeof(server_ef_keyerr) == 0) || std::memcmp(begin, server_df_msgerr, sizeof(server_df_msgerr) == 0)) {
                        offset += 1 + ERR_CODE_BYTES;
                        std::copy(begin + offset, begin + offset + CIF_BYTES, cinfo_hash_bytes.begin());
                        offset += CIF_BYTES;
                        auto cif = session_item::bytes_to_u64(cinfo_hash_bytes);
                        if(cif == session.get_cinfo_hash()) {
                            std::copy(begin + offset, begin + offset + crypto_box_PUBLICKEYBYTES, recved_server_pk.begin());
                            server_pk_mgr.update_server_pk(recved_server_pk);
                            session.reset();
                            continue;
                        }
                    }
                }
                if(header != 0x02) 
                    continue; // Now, only handles 0x02 header.
                    // Expected: 0x02 + aes_nonce + encrypted(sid + cif + ok + checksum)
                if(buffer.recv_raw_bytes != 1 + crypto_aead_aes256gcm_NPUBBYTES + SID_BYTES + CIF_BYTES + sizeof(ok) + crypto_aead_aes256gcm_ABYTES)
                    continue; // Invalid message length.
                ++ offset;
                std::copy(begin + offset, begin + offset + crypto_aead_aes256gcm_NPUBBYTES, server_aes_nonce.begin());
                offset += crypto_aead_aes256gcm_NPUBBYTES;
                auto is_aes_ok = 
                    (crypto_aead_aes256gcm_decrypt(
                        buffer.recv_aes_buffer.begin(), (unsigned long long *)(&aes_decrypted_len),
                        NULL,
                        begin + offset, SID_BYTES + CIF_BYTES + sizeof(ok) + crypto_aead_aes256gcm_ABYTES,
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
            // Now the status == 3.
        }
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
            std::cout << "Will use the default server localhost:8081." << std::endl;
        }
        else
            std::cout << "Will connect to the provided server " << addr_str << ":" << port_str << std::endl;
    }
    else
        std::cout << "Will use the default server localhost:8081." << std::endl;
    
    if(!new_client.start_client()) {
        std::cout << "Failed to start client. Error Code: " 
                  << new_client.get_last_error() << std::endl;
        return 3;
    }
    return new_client.run_client();
}