# Technical Review: Build A Chatroom in 400 Lines of C++ Codes

## 1. Background

A chatroom is a web service that allows multiple users to join and post messages to others. In this practice, we will build a chatroom based on the stateless protocol UDP. The language is C++ with support from libsodium (for hashing) and socket (for UDP communication).

Repo: `https://github.com/zhenrong-wang/random-codes/` -> Code: `udp_chatroom.cpp` 

## 2. Architecture

```
UDP Clients -- Chatroom Server -- User, Client, and Message Management
     |          /
Service Users -'
```

## 3. Step-by-step

### 3.1 Include Headers

The code needs socket programming and libsodium for hashing passwords, so we need to include them.

```
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
```

### 3.2 Define Constants

We use `constexpr` to define constants that will be used in the following code.

```
constexpr uint16_t default_port = 8081;
constexpr size_t init_buffsize = 1024;
constexpr char main_menu[] = "1. signup\n2. signin\nPlease choose (1 | 2): ";
constexpr char input_username[] = "Username: ";
constexpr char input_password[] = "Password: ";
constexpr char option_error[] = "option error, please input 1 or 2\n";
constexpr char user_uid_exist[] = "user already exist.\n";
constexpr char user_uid_error[] = "user not exist.\n";
constexpr char password_error[] = "password doesn't match.\n";
constexpr char signup_ok[] = "signed up and signed in.\nq! to sign out.\n";
constexpr char signin_ok[] = "signed in.\nsend ~:q! to sign out.\n";
constexpr char signed_out[] = "!!! signed out.\n";
constexpr char user_already_signin[] = "user already signed in at: ";
```

### 3.3 Define a Class for Signed Users

For a multi-user service, we need to manage user information, including unique ID and passwords. Usually we don't manage the passwords, instead, we manage the hashed passwords for security. 

First, let's define a struct containing user_uid and pass_hash:

```
struct user_entry {
    std::string user_uid;   // Unique ID
    std::string pass_hash;  // Hashed password
};
```
Now, we can define the user_store class to manage the users.

```
class user_store {
    std::vector<struct user_entry> users; // Vector of users
public:
    // Hash a password using libsodium API
    static std::string get_pass_hash(std::string password); 

    // Get the index of users<> of a user_uid
    ssize_t get_user_idx(std::string user_uid); 

    // Whether the user_uid is already stored
    bool is_in_store(std::string user_uid); 
    
    // Whether the uid and password match
    bool is_user_pass_valid(std::string user_uid, std::string provided_password); 
};
```

### 3.4 Define a Class for Connection Contexts

A context in this project, including three things:

- An address (Client IP + Port)
- A status
- A binded / empty user_uid

We can then define set/get method pairs.

```
class conn_ctx {
    struct sockaddr_in conn_addr;   // Connection Addr Info
    std::string conn_bind_uid;      // Binded/Empty user unique ID
    int conn_status;                // Connection Status
public:
    conn_ctx();
    const struct sockaddr_in* get_conn_addr() const;
    void set_conn_addr(struct sockaddr_in addr);
    std::string get_bind_uid() const;
    void set_bind_uid(std::string uid);
    void reset_conn();
    int get_status() const;
    void set_status(int status);
};
```
The status are:

- 0: standby
- 1: waiting for main option (signup or signin)
- 2: option signup, waiting for username (user_uid)
- 3: option signin, waiting for username (user_uid)
- 4: option signup, username is valid, waiting for password
- 5: option signin, username is valid, waiting for password
- 6: signed up and signed in, ok for communicating

### 3.5 The Main Class: udp_chatroom

With the building blocks above, we can design the `udp_chatroom` main class, it includes several private members:

```
class udp_chatroom {
    struct sockaddr_in address; // socket addr
    uint16_t port;              // port number
    int server_fd;              // generated server file descriptor
    size_t buff_size;           // io buffer size
    int err_code;               // error code
    user_store all_users;       // all users
    std::vector<conn_ctx> clients; // clients
public:
    // Main methods.
    // See the details below. 
}
```
Then, we can define several methods to drive the server:

```
    // A simple constructor
    udp_chatroom();

    // You can add more constructors to initialize a server.
    // ...

    // Close server and possible FD
    bool close_server(int err);

    // Get last error code
    int get_last_error(void);

    // Start the server and handle possible failures
    bool start_server(void);
    
    // Get the vector index of clients<> according to a client_addr
    ssize_t get_conn_idx(struct sockaddr_in client_addr);

    // Whether an addr is already in the clients<> pool or not.
    bool is_connected(struct sockaddr_in client_addr);

    // Assemble the message header for a connection context
    std::string assemble_msg_header(conn_ctx& ctx);

    // Simplify the socket send function.
    int simple_send(const void *buff, size_t n, struct sockaddr_in client_addr);

    // Convert an addr to a message
    std::string addr_to_msg(const struct sockaddr_in addr);

    // Get the index of clients<> according to a user_uid
    ssize_t get_client_idx(std::string user_uid);

    // Broadcasting to all connected clients (include or exclude current/self).
    size_t system_broadcasting(bool include_self, std::string user_uid, std::string& msg_body);

    // Main processing method.
    // It manages all clients, users, status, and messages
    // Please check the source code for details.
    int run_server(void);

```

### 3.6 The `Main()`

Because we only defined the default constructor that uses all default values, here the `main()` is also simple - the `args` are not used.

```
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
```
One can make it more sophisticated but that would probably need extra constructors.

## 4. Summary

With the methods and designs above, we can make a simplest UDP-based chatroom from scratch. It is useful for learning C++, Socket Programming, and OOP method.

The code is probably buggy because I wrote it quickly, and it was designed for demonstration purposes. Please feel free to submit issues and improve the codes.
