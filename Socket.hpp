#pragma once

// Platform includes
#ifdef _WIN32
#    define WIN32_LEAN_AND_MEAN
#    include <windows.h>
#    include <winsock2.h>
#    pragma comment(lib, "ws2_32.lib")
#else
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

    SocketJanitor()                                = default;
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

} // namespace lichat::net
