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

constexpr size_t uid_maxlen = 64;
constexpr size_t uid_minlen = 4;
constexpr size_t password_maxlen = 32;
constexpr size_t password_minlen = 4;
constexpr uint16_t default_port = 8081;
constexpr size_t init_buffsize = 1024;
constexpr char special_chars[] = "~!@#$%^&(){}[]-_=+;:,.<>/|";
constexpr char main_menu[] = "1. signup\n2. signin\nPlease choose (1 | 2): ";
constexpr char input_username[] = "Username: ";
constexpr char input_password[] = "Password: ";
constexpr char option_error[] = "option error, please input 1 or 2\n";
constexpr char user_uid_exist[] = "user already exists.\n";
constexpr char user_uid_error[] = "user does not exist.\n";
constexpr char password_error[] = "password doesn't match.\n";
constexpr char length_error[] = "invalid length. user_uid: 4-64. password: 4-32\n";
constexpr char invalid_char_error[] = "invalid char.\nuser_uid: A(a)lphabet, numbers, and hyphen-\nuser_password: A(a)lphabet, numbers, and special chars, no spaces.\n";
constexpr char signup_ok[] = "signed up and signed in.\nsend ~:q! to sign out.\n";
constexpr char signin_ok[] = "signed in.\nsend ~:q! to sign out.\n";
constexpr char signed_out[] = "[SYSTEM] you have signed out.\n";
constexpr char user_already_signin[] = "user already signed in at: ";
constexpr char cannot_at_or_to_user[] = "[SYSTEM] target user not signed in.\n";
constexpr char cannot_at_or_to_self[] = "[SYSTEM] you cannot tag or send message to yourself.\n";
constexpr char been_tagged[] = "[SYSTEM] you've been tagged !\n";
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
};

struct msg_attr {
    uint8_t msg_attr_mask;  // 00 - public & untagged;
                            // 01 - public but tagged (target_uid and target_ctx_idx valid)
                            // 02 - private (target_uid and target_ctx_idx valid)
    std::string target_uid;
    ssize_t target_ctx_idx;

    msg_attr() {
        msg_attr_mask = 0;
        target_uid.clear();
        target_ctx_idx = -1;
    }
};

// Connection Context contains an addr, a bind/empty uid, and a status
class conn_ctx {
    struct sockaddr_in conn_addr;   // Connection Addr Info
    std::string conn_bind_uid;      // Binded/Empty user unique ID
    int conn_status;                // Connection Status
public:
    conn_ctx() {
        std::memset(&conn_addr, 0, sizeof(conn_addr));
        conn_bind_uid.clear();
        conn_status = 0;
    }
    const struct sockaddr_in* get_conn_addr() const {
        return &conn_addr;
    }
    void set_conn_addr(struct sockaddr_in addr){
        conn_addr = addr;
    }
    std::string get_bind_uid() const {
        return conn_bind_uid;
    }
    void set_bind_uid(std::string uid) {
        conn_bind_uid = uid;
    }
    void reset_conn() {
        conn_bind_uid.clear();
        conn_status = 0;
    }
    int get_status() const {
        return conn_status;
    }
    void set_status(int status) {
        conn_status = status;
    }
};

// The user storage is in memory, no persistence. Just for demonstration.
// Please consider using a database if you'd like to go further.
class user_database {
    std::unordered_map<std::string, user_entry> user_db;
public:
    static std::string get_pass_hash(std::string password) {
        std::string ret;
        char hashed_pwd[crypto_pwhash_STRBYTES];
        if(crypto_pwhash_str(
            hashed_pwd, 
            (password.c_str()), 
            password.size(), 
            crypto_pwhash_OPSLIMIT_INTERACTIVE, 
            crypto_pwhash_MEMLIMIT_INTERACTIVE
            ) == 0 ) {
            ret = hashed_pwd;
        };
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
        for(auto c : pass_str) {
            if(!std::isalnum(static_cast<unsigned char>(c)) && special.find(c) == std::string::npos)
                return 1;
        }
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
        return true;
    }
    bool is_user_pass_valid(std::string user_uid, std::string provided_password) {
        if(user_uid.empty() || provided_password.empty())
            return false;
        if(!is_in_db(user_uid))
            return false;
        auto ptr_user = get_user_entry(user_uid);
        if(ptr_user == nullptr)
            return false;
        return crypto_pwhash_str_verify(
            (ptr_user->pass_hash).c_str(), 
            provided_password.c_str(), 
            provided_password.size()) == 0;
    }
};

// The main class.
class udp_chatroom {
    struct sockaddr_in address; // socket addr
    uint16_t port;              // port number
    int server_fd;              // generated server file descriptor
    size_t buff_size;           // io buffer size
    int err_code;               // error code
    user_database all_users;       // all users
    std::vector<conn_ctx> clients; // clients
    
public:
    // A simple constructor
    udp_chatroom() {
        server_fd = -1;
        port = default_port;
        err_code = 0;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        buff_size = init_buffsize;
        clients.clear();
    }

    // You can add more constructors to initialize a server.
    // ...

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
        if(bind(server_fd, (sockaddr *)&address, (socklen_t)sizeof(address)))
            return close_server(3);
        std::cout << "UDP Chatroom Service started." << std::endl << "UDP Listening Port: " << port << std::endl;
        return true;
    }
    
    // Get the vector index of clients<> according to a client_addr
    ssize_t get_conn_idx(struct sockaddr_in client_addr) {
        auto it = std::find_if(clients.begin(), clients.end(), [&client_addr](const conn_ctx& ctx_elem) {
            struct sockaddr_in ctx_addr = *(ctx_elem.get_conn_addr());
            return ((client_addr.sin_addr.s_addr == ctx_addr.sin_addr.s_addr) &&
                    (client_addr.sin_family == ctx_addr.sin_family) &&
                    (client_addr.sin_port == ctx_addr.sin_port));
        });
        if(it == clients.end())
            return clients.size();
        return std::distance(clients.begin(), it);
    }

    // Whether an addr is already in the clients<> pool or not.
    bool is_connected(struct sockaddr_in client_addr) {
        return get_conn_idx(client_addr) != clients.size();
    }

    // Simplify the socket send function.
    int simple_send(const void *buff, size_t n, struct sockaddr_in client_addr) {
        auto ret = sendto(server_fd, buff, n, MSG_CONFIRM, (struct sockaddr *)&client_addr, sizeof(client_addr));
        if(ret < 0) {
            auto idx = get_conn_idx(client_addr);
            clients.erase(clients.begin() + idx); // If socket error, just delete the connection
        }
        return ret;
    }

    // Convert an addr to a message
    std::string addr_to_msg(const struct sockaddr_in addr) {
        std::ostringstream oss;
        char ip_cstr[INET_ADDRSTRLEN];
        std::strncpy(ip_cstr, inet_ntoa(addr.sin_addr), INET_ADDRSTRLEN);
        oss << ip_cstr << ":" << ntohs(addr.sin_port) << std::endl;
        return oss.str();
    }

    // Get the index of clients<> according to a user_uid
    size_t get_client_idx(std::string user_uid) {
        auto it = std::find_if(clients.begin(), clients.end(), [&user_uid](const conn_ctx& elem) {
            return elem.get_bind_uid() == user_uid;
        });
        if(it == clients.end()) 
            return clients.size();
        else
            return std::distance(clients.begin(), it);
    }

    bool is_user_signed_in(std::string user_uid) {
        return get_client_idx(user_uid) != clients.size();
    }

    // Broadcasting to all connected clients (include or exclude current/self).
    size_t system_broadcasting(bool include_self, std::string user_uid, std::string& msg_body) {
        std::string msg = "[SYSTEM BROADCASTING]: [UID]";
        msg += user_uid;
        msg += msg_body;
        size_t sent_out = 0;
        for(auto& item : clients) {
            if(item.get_status() != 6)
                continue;
            if(item.get_bind_uid() == user_uid && !include_self)
                continue;
            if(simple_send(msg.c_str(), msg.size(), *(item.get_conn_addr())) >=0 )
                ++ sent_out;
        }
        return sent_out;
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

    int msg_precheck(const conn_ctx& this_ctx, const std::string& buff_str, struct msg_attr& attr) {
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
            if(all_users.is_in_db(target_user)) { // If the target uid is valid
                if(!is_user_signed_in(target_user))
                    return 1;   // tagged or private message requires target user signed in.
                                // false will bounce the msg back to sender.
                attr.target_uid = target_user;
                attr.target_ctx_idx = get_client_idx(target_user);
                if(!is_private_msg) 
                    attr.msg_attr_mask = 1; // Public but tagged
                else
                    attr.msg_attr_mask = 2; // Private
                return 0; // msg_attr_mask set and return true
            }
            // If the target user uid is invalid, do nothing
            return 0;
        }
        // If normal message, do nothing.
        return 0;
    } 

    // Assemble the message header for a connection context
    std::string assemble_msg_header(const conn_ctx& ctx) {
        struct sockaddr_in addr = *(ctx.get_conn_addr());
        char ip_cstr[INET_ADDRSTRLEN];
        std::strncpy(ip_cstr, inet_ntoa(addr.sin_addr), INET_ADDRSTRLEN);
        std::string curr_time = get_current_time();
        std::ostringstream oss;
        oss << std::endl << curr_time << " [FROM_ADDR] " 
            << ip_cstr << ":" << ntohs(addr.sin_port) 
            << " [FROM_UID] " << ctx.get_bind_uid() << ":" << std::endl << "----  ";
        return oss.str(); 
    }

    // Must call msg_precheck first!!!
    void update_msg_buffer(std::vector<char>& buffer, const struct msg_attr& attr, const conn_ctx& ctx) {
        std::string msg_header = assemble_msg_header(ctx);
        if(attr.msg_attr_mask != 0)
            buffer.erase(buffer.begin(), buffer.begin() + MSG_ATTR_LEN + attr.target_uid.size() + 1);
        if(attr.msg_attr_mask == 1) 
            msg_header += (std::string("@tagged@") + attr.target_uid + std::string(" "));
        else if(attr.msg_attr_mask == 2)
            msg_header += (std::string("*private*") + std::string(" "));
        buffer.insert(buffer.begin(), msg_header.c_str(), msg_header.c_str() + msg_header.size());
        buffer.back() = '\n';
        buffer.push_back('\n');
        buffer.push_back('\0');
    }

    // Main processing method.
    int run_server(void) {
        if(server_fd == -1) {
            std::cout << "Server not started." << std::endl;
            return -1;
        }
        struct sockaddr_in client_addr;
        size_t addr_len = sizeof(client_addr);
        std::vector<char> buffer(buff_size, 0);
        std::string msg_header;
        while(true) {
            std::fill(buffer.begin(), buffer.end(), 0);
            auto bytes_recv = recvfrom(server_fd, buffer.data(), buffer.size(), \
                MSG_WAITALL, (struct sockaddr *)&client_addr, (socklen_t *)&addr_len);
            if(bytes_recv < 0)
                return close_server(-3);
            buffer[bytes_recv - 1] = '\0'; // Omit the '\n' char.
            std::string buff_str = buffer.data();
            std::cout << ">> Received from: " << std::endl << inet_ntoa(client_addr.sin_addr) \
                      << ':' << ntohs(client_addr.sin_port) << '\t' << buffer.data() << std::endl;
            auto conn_idx = get_conn_idx(client_addr);
            if(conn_idx == clients.size()) {
                conn_ctx new_conn;
                new_conn.set_conn_addr(client_addr);
                simple_send(main_menu, sizeof(main_menu), client_addr);
                new_conn.set_status(1);
                clients.push_back(new_conn);
            }
            else {
                auto& client = clients[conn_idx];
                auto stat = client.get_status();
                if(stat == 0) {
                    simple_send(main_menu, sizeof(main_menu), client_addr);
                    client.set_status(1);
                }
                else if(stat == 1) {
                    if(buff_str == "1") {
                        simple_send(input_username, sizeof(input_username), client_addr);
                        client.set_status(2); // Sign up
                    }
                    else if(buff_str == "2") {
                        simple_send(input_username, sizeof(input_username), client_addr);
                        client.set_status(3); // Sign in
                    }
                    else {
                        simple_send(option_error, sizeof(option_error), client_addr);
                        client.reset_conn();
                    }
                }
                else if(stat == 2 || stat == 3) {
                    int flag = all_users.user_uid_check(buff_str);
                    if(flag == -1) {
                        simple_send(length_error, sizeof(length_error), client_addr);
                        client.reset_conn(); continue;
                    }
                    if(flag == 1) {
                        simple_send(invalid_char_error, sizeof(invalid_char_error), client_addr);
                        client.reset_conn(); continue;
                    }
                    if(stat == 2) {
                        if(all_users.is_in_db(buff_str)) {
                            simple_send(user_uid_exist, sizeof(user_uid_exist), client_addr);
                            client.reset_conn();
                        }
                        else {
                            simple_send(input_password, sizeof(input_password), client_addr);
                            client.set_bind_uid(buff_str);
                            client.set_status(4);
                        }
                    }
                    else {
                        if(!all_users.is_in_db(buff_str)) {
                            simple_send(user_uid_error, sizeof(user_uid_error), client_addr);
                            client.reset_conn();
                        }
                        else {
                            auto client_idx = get_client_idx(buff_str);
                            if(client_idx != clients.size()) {
                                simple_send(user_already_signin, sizeof(user_already_signin), client_addr);
                                std::string addr_msg = addr_to_msg(*(client.get_conn_addr()));
                                simple_send(addr_msg.c_str(), addr_msg.size(), client_addr);
                                client.reset_conn();
                            }
                            else {
                                simple_send(input_password, sizeof(input_password), client_addr);
                                client.set_bind_uid(buff_str);
                                client.set_status(5);
                            }
                        }
                    }
                }
                else if(stat == 4 || stat == 5) {
                    int flag = all_users.pass_str_check(buff_str);
                    if(flag == -1) {
                        simple_send(length_error, sizeof(length_error), client_addr);
                        client.reset_conn(); continue;
                    }
                    if(flag == 1) {
                        simple_send(invalid_char_error, sizeof(invalid_char_error), client_addr);
                        client.reset_conn(); continue;
                    }
                    std::string user_uid = client.get_bind_uid();
                    if(stat == 4) {
                        all_users.add_user(user_uid, buff_str);
                        simple_send(signup_ok, sizeof(signup_ok), client_addr);
                        std::string msg_body = " signed up and in !\n";
                        system_broadcasting(false, user_uid, msg_body);
                        client.set_status(6);
                    }
                    else {
                        if(all_users.is_user_pass_valid(user_uid, buff_str)) {
                            simple_send(signin_ok, sizeof(signin_ok), client_addr);
                            std::string msg_body = " signed in !\n";
                            system_broadcasting(false, user_uid, msg_body);
                            client.set_status(6);
                        }
                        else {
                            simple_send(password_error, sizeof(password_error), client_addr);
                            client.reset_conn();
                        }
                    }
                }
                else {
                    std::string user_uid = client.get_bind_uid();
                    if(buff_str == "~:q!") {
                        simple_send(signed_out, sizeof(signed_out), client_addr);
                        std::string msg_body = " signed out !\n";
                        system_broadcasting(false, user_uid, msg_body);
                        client.reset_conn();
                    }
                    else {
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
                        update_msg_buffer(buffer, attr, client);
                        if(attr.msg_attr_mask == 0) {
                            for(auto& item : clients) {
                                if(item.get_status() == 6)
                                    simple_send(buffer.data(), buffer.size(), *(item.get_conn_addr()));
                            }
                        }
                        else if(attr.msg_attr_mask == 1) {
                            for(auto& item : clients) {
                                if(item.get_status() == 6) {
                                    if(item.get_bind_uid() == attr.target_uid)
                                        simple_send(been_tagged, sizeof(been_tagged), *(clients[attr.target_ctx_idx].get_conn_addr()));
                                    simple_send(buffer.data(), buffer.size(), *(item.get_conn_addr()));
                                }
                            }
                        }
                        else {
                            simple_send(buffer.data(), buffer.size(), *(clients[attr.target_ctx_idx].get_conn_addr()));
                        }
                    }
                }
            }
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
