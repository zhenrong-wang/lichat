#pragma once

// Project includes
#include "lc_common.hpp"

// Platform includes
#ifdef _WIN32
#    define WIN32_LEAN_AND_MEAN
#    include <windows.h>
#    include <winsock2.h>
#    include <ws2ipdef.h>
#    include <ws2tcpip.h>
#    pragma comment(lib, "ws2_32.lib")
#else
#    include <fcntl.h>
#    include <sys/socket.h>
#    include <unistd.h>
#endif

#include <format>
#include <stdexcept>
#include <string>
#include <unordered_map>

namespace lichat::net {
#ifdef _WIN32
using socket_t = ::SOCKET;
using ssize_t  = int;
#    define SOCKET_ERROR_VALUE   SOCKET_ERROR
#    define INVALID_SOCKET_VALUE INVALID_SOCKET
#    define CLOSE_SOCKET(s)      closesocket(s)
#    define MSG_CONFIRM 0
#else
using socket_t = int;
#    define SOCKET_ERROR_VALUE   (-1)
#    define INVALID_SOCKET_VALUE (-1)
#    define CLOSE_SOCKET(s)      close(s)
#endif

inline auto get_last_socket_error() -> std::string
{
#ifdef _WIN32
    auto out = std::string(256, '\0');
    ::FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, WSAGetLastError(),
                     MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), out.data(), out.size(), NULL);
    return out;
#else
    return std::string{strerror(errno)};
#endif
}

enum class SocketErrorCode { createSocketFailed = 1, bindFailed, setTimeoutFailed };
} // namespace lichat::net

[[nodiscard]] auto to_string(lichat::net::SocketErrorCode ec) -> const std::string&
{
    static const auto lookup = std::unordered_map<lichat::net::SocketErrorCode, std::string>{
        {lichat::net::SocketErrorCode::createSocketFailed, "create socket failed"},
        {lichat::net::SocketErrorCode::bindFailed, "bind failed"},
        {lichat::net::SocketErrorCode::setTimeoutFailed, "set timeout failed"},
    };

    return lookup.at(ec);
}

[[nodiscard]] auto as_int(lichat::net::SocketErrorCode ec) -> int
{
    return static_cast<int>(ec);
}

namespace lichat::net {
class SocketException : public std::runtime_error {
    SocketErrorCode error_code_{};

public:
    explicit SocketException(const char* msg, SocketErrorCode error_code)
        : std::runtime_error{std::format("[Socket Exception] {} ({}): {}", msg, static_cast<int>(error_code),
                                         lichat::net::get_last_socket_error())}
        , error_code_{error_code}
    {
    }

    [[nodiscard]] auto error_code() const noexcept
    {
        return error_code_;
    }
};

struct SocketJanitor {
    socket_t handle{INVALID_SOCKET_VALUE};

    SocketJanitor()                                = delete;
    SocketJanitor(const SocketJanitor&)            = delete;
    SocketJanitor& operator=(const SocketJanitor&) = delete;
    SocketJanitor(SocketJanitor&& other) noexcept : handle{std::exchange(other.handle, INVALID_SOCKET_VALUE)} {}
    SocketJanitor& operator=(SocketJanitor&& other) noexcept
    {
        handle = std::exchange(other.handle, INVALID_SOCKET_VALUE);
        return *this;
    }

    explicit SocketJanitor(socket_t handle) : handle{handle} {}
    ~SocketJanitor()
    {
        if (handle != INVALID_SOCKET_VALUE) {
            CLOSE_SOCKET(handle);
        }
    }
};

auto make_sockaddr_in(uint16_t port) -> ::sockaddr_in
{
    auto out            = ::sockaddr_in{};
    out.sin_family      = AF_INET;
    out.sin_addr.s_addr = INADDR_ANY;
    out.sin_port        = htons(port);
    return out;
}

auto try_make_sockaddr_in(const std::string& address, uint16_t port) -> std::optional<::sockaddr_in>
{
    auto hints = addrinfo{};

    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    const auto port_num_str = std::to_string(port);

    addrinfo* result = nullptr;
    if (::getaddrinfo(address.c_str(), port_num_str.c_str(), &hints, &result) != 0) {
        return {};
    }

    // Use the first result
    auto out = ::sockaddr_in{};
    memcpy(&out, result->ai_addr, result->ai_addrlen);
    freeaddrinfo(result);

    return out;
}

auto make_sockaddr_in(const std::string& address, uint16_t port) -> ::sockaddr_in
{
    auto out = try_make_sockaddr_in(address, port);
    if (not out) {
        throw std::runtime_error{std::format("Failed to create sockaddr_in from address: {}, port: {}", address, port)};
    }

    return out.value();
}

[[nodiscard]] auto make_socket_nonblocking(socket_t socket_handle) -> bool
{
#ifdef _WIN32
    auto mode = u_long{1};
    if (ioctlsocket(socket_handle, FIONBIO, &mode) == SOCKET_ERROR) {
        auto const error = WSAGetLastError();
        std::cerr << "Failed to set socket to non-blocking mode. Error: " << error << std::endl;
        return false;
    }

    return true;
#else
    auto flags = fcntl(socket_handle, F_GETFL, 0);
    if (flags == -1) {
        return false;
    }

    flags |= O_NONBLOCK;
    if (fcntl(socket_handle, F_SETFL, flags) == -1) {
        return false;
    }

    return true;
#endif
}

} // namespace lichat::net
