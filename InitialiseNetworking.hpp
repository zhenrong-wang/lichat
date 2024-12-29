// Project includes
#include "Socket.hpp"

// Platform includes
#ifdef _WIN32
#    define WIN32_LEAN_AND_MEAN
#    include <ws2tcpip.h>
#else
#    include <arpa/inet.h>
#    include <fcntl.h>
#    include <netinet/in.h
#endif

// C++ std lib includes
#include <stdexcept>
#include <string>

namespace lichat::net {
#ifdef _WIN32
class NetworkingInitializer {
public:
    NetworkingInitializer()
    {
        auto wsaData = ::WSADATA{};
        if (::WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            throw std::runtime_error{"Failed to initialize Winsock"};
        }
    }

    ~NetworkingInitializer()
    {
        WSACleanup();
    }
};
#else
class NetworkingInitializer {};
#endif
} // namespace lichat::net
