// This is the *simplest* UDP (Message based) echo server in C++ for learning

#include <iostream>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <vector>

#define DEFAULT_PORT 8081
#define INIT_BUFFSIZE 1024

class echo_server_udp {
    struct sockaddr_in address; // socket addr
    uint16_t port;              // port number
    int server_fd;              // generated server file descriptor
    size_t buff_size;           // io buffer size
    int err_code;               // error code
    
public:
    // A simple constructor
    echo_server_udp() {
        server_fd = -1;
        port = DEFAULT_PORT;
        err_code = 0;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        buff_size = INIT_BUFFSIZE;
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
        server_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if(server_fd == -1)
            return close_server(1);
        if(bind(server_fd, (sockaddr *)&address, (socklen_t)sizeof(address)))
            return close_server(3);
        std::cout << "UDP Listening Port: " << port << std::endl;
        return true;
    }

    // Accept messages and echo back
    int run_server(void) {
        if(server_fd == -1) {
            std::cout << "Server not started." << std::endl;
            return -1;
        }
        struct sockaddr_in client_addr;
        size_t addr_len = sizeof(client_addr);
        std::vector<char> buffer(buff_size, 0);
        while(true) {
            if(recvfrom(server_fd, buffer.data(), buffer.size(), MSG_WAITALL, 
            (struct sockaddr *)&client_addr, (socklen_t *)&addr_len) < 0)
                return close_server(-3);
            std::cout << ">> Received from: " << std::endl << inet_ntoa(client_addr.sin_addr)
                      << ':' << ntohs(client_addr.sin_port) << '\t' << buffer.data() << std::endl;
            if(sendto(server_fd, buffer.data(), buffer.size(), MSG_CONFIRM,
            (struct sockaddr *)&client_addr, addr_len) < 0)
                return close_server(-5);
            std::cout << "<< Echoed back to: " << inet_ntoa(client_addr.sin_addr)
                      << ':' << ntohs(client_addr.sin_port) << std::endl << std::endl;
            std::fill(buffer.begin(), buffer.end(), 0);
        }
    }
};

int main(int argc, char **argv) {
    echo_server_udp new_server;
    if(!new_server.start_server()) {
        std::cout << "Failed to start server. Error Code: " 
                  << new_server.get_last_error() << std::endl;
        return 1;
    }
    return new_server.run_server();
}
