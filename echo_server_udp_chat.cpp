// This is the *simplest* UDP (Message based) echo server in C++ for learning

#include <iostream>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <vector>
#include <set>
#include <cstring>

constexpr uint16_t default_port = 8081;
constexpr size_t init_buffsize = 1024;

struct sockaddr_in_compare {
    bool operator()(const struct sockaddr_in a, const struct sockaddr_in b) {
        if(a.sin_family != b.sin_family)
            return a.sin_family < b.sin_family;
        if(a.sin_addr.s_addr < b.sin_addr.s_addr) 
            return true;
        else if(a.sin_addr.s_addr > b.sin_addr.s_addr)
            return false;
        else
            return a.sin_port < b.sin_port;
    }
};

class echo_server_udp {
    struct sockaddr_in address; // socket addr
    uint16_t port;              // port number
    int server_fd;              // generated server file descriptor
    size_t buff_size;           // io buffer size
    int err_code;               // error code
    std::set<sockaddr_in, sockaddr_in_compare> clients; //Client addrs
    
public:
    // A simple constructor
    echo_server_udp() {
        server_fd = -1;
        port = default_port;
        err_code = 0;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        buff_size = init_buffsize;
        clients.clear();
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
        std::string msg_header;
        while(true) {
            if(recvfrom(server_fd, buffer.data(), buffer.size(), MSG_WAITALL, \
            (struct sockaddr *)&client_addr, (socklen_t *)&addr_len) < 0)
                return close_server(-3);
            std::cout << ">> Received from: " << std::endl << inet_ntoa(client_addr.sin_addr) \
                      << ':' << ntohs(client_addr.sin_port) << '\t' << buffer.data() << std::endl;

            clients.insert(client_addr);

            char ip_cstr[INET_ADDRSTRLEN];
            std::strncpy(ip_cstr, inet_ntoa(client_addr.sin_addr), INET_ADDRSTRLEN);
            std::string ip_str(ip_cstr);
            std::string ch1(":");
            std::string port_str = std::to_string(ntohs(client_addr.sin_port));
            std::string ch2("\t");
            
            msg_header =  ip_str + ch1 + port_str + ch2; 

            buffer.insert(buffer.begin(), msg_header.c_str(), msg_header.c_str() + msg_header.size());
            
            for(std::set<sockaddr_in, sockaddr_in_compare>::const_iterator \
                it = clients.begin(); it != clients.end(); ++ it) {
                const sockaddr_in& elem = *it;
                if(sendto(server_fd, buffer.data(), buffer.size(), MSG_CONFIRM, \
                (struct sockaddr *)&elem, addr_len) < 0) {
                    std::cout << "<< Failed to echo: " << inet_ntoa(elem.sin_addr) \
                    << ':' << ntohs(elem.sin_port) << std::endl << std::endl;
                    return close_server(-5);
                }
            }
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
