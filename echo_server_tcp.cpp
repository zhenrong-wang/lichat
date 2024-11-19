// This is the *simplest* echo server in C++ just for learning
// It uses POSIX threads to make non-blocking possible, but that's not
// a good way. In production, please use event loops or other approaches, they
// are much better than multithreading here.

#include <iostream>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <thread>
#include <vector>

#define DEFAULT_PORT 8080
#define DEFAULT_BACKLOG 3
#define DEFAULT_BUFFSIZE 1024

class echo_server_tcp {
    struct sockaddr_in address; // socket addr
    uint16_t port;              // port number
    int server_fd;              // generated server file descriptor
    int backlog;                // backlog
    size_t buff_size;           // io buffer size
    int err_code;               // error code
    
public:
    // A simple constructor
    echo_server_tcp() {
        server_fd = -1;
        port = DEFAULT_PORT;
        err_code = 0;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        backlog = DEFAULT_BACKLOG;
        buff_size = DEFAULT_BUFFSIZE;
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
        server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if(server_fd == -1)
            return close_server(1);
        if(bind(server_fd, (sockaddr *)&address, (socklen_t)sizeof(address)))
            return close_server(3);
        if(listen(server_fd, backlog))
            return close_server(5);
        std::cout << "TCP Listening Port: " << port << std::endl;
        return true;
    }

    // Client thread workload
    void client_thread(int client_fd) {
        std::vector<char> buffer(buff_size, 0);
        ssize_t num_bytes;
        while((num_bytes = recv(client_fd, buffer.data(), buffer.size(), 0)) > 0) {
            buffer[num_bytes] = '\0';
            send(client_fd, buffer.data(), num_bytes, 0);
            std::fill(buffer.begin(), buffer.end(), 0);
        }
        if(num_bytes == 0)
            std::cout << "Client connection closed." << std::endl;
        else
            std::cout << "Error receiving data from client." << std::endl;
        close(client_fd);
    }

    // Accept cconnections and handle them to new threads
    int run_server(void) {
        if(server_fd == -1) {
            std::cout << "Server not started." << std::endl;
            return -1;
        }
        size_t addr_len = sizeof(address);
        int new_conn = accept(server_fd, (sockaddr *)&address, (socklen_t *)&addr_len);
        if(new_conn == -1) {
            std::cout << "Failed to accept a new connection." << std::endl;
            return -3;
        }
        std::cout << "A new connection established." << std::endl;
        std::thread client_thread(&echo_server_tcp::client_thread, this, new_conn);
        client_thread.detach(); 
        return 0; 
    }
};

int main(int argc, char **argv) {
    echo_server_tcp new_server;
    if(!new_server.start_server()) {
        std::cout << "Failed to start server. Error Code: " 
                  << new_server.get_last_error() << std::endl;
        return 1;
    }
    while(1) {
        new_server.run_server();
    }
    return 0;
}
