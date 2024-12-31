#include "Bytes.hpp"
#include "Socket.hpp"

namespace lichat::net {
class ServerSocket {
    ::sockaddr_in address_info{};
    socket_t      native_socket{INVALID_SOCKET_VALUE};
    SocketJanitor socket_janitor;

    [[nodiscard]] static auto set_socket_timeout(socket_t native_socket)
    {
#ifdef _WIN32
        DWORD timeout = SERVER_RECV_WAIT_SECS * 1000;
#else
        struct timeval timeout;
        timeout.tv_sec  = SERVER_RECV_WAIT_SECS;
        timeout.tv_usec = 0;
#endif

        return ::setsockopt(native_socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    }

    [[nodiscard]] auto init_native_socket(socket_t native, ::sockaddr_in& address_info) -> SocketJanitor
    {
        if (native_socket == INVALID_SOCKET_VALUE) {
            throw SocketException{"Socket creation failed", SocketErrorCode::createSocketFailed};
        }

        auto socketCloser = SocketJanitor(native_socket);

        if (::bind(native_socket, reinterpret_cast<sockaddr*>(&address_info), sizeof(address_info)) == SOCKET_ERROR_VALUE) {
            throw SocketException{"Bind failed", SocketErrorCode::bindFailed};
        }

        if (set_socket_timeout(native_socket) == SOCKET_ERROR_VALUE) {
            throw SocketException{"Failed to set socket timeout", SocketErrorCode::setTimeoutFailed};
        }

        std::cout << "LightChat (LiChat) Service started.\nUDP Listening Port: " << htons(address_info.sin_port) << std::endl;

        return socketCloser;
    }

public:
    ServerSocket(uint16_t port)
        : address_info{make_sockaddr_in(port)}
        , native_socket{::socket(AF_INET, SOCK_DGRAM, 0)}
        , socket_janitor{init_native_socket(native_socket, address_info)}
    {
    }

    [[nodiscard]] auto port() const noexcept -> uint16_t
    {
        return htons(address_info.sin_port);
    }

    auto send_to(const ::sockaddr_in& dest_address_info, const_byte_span_t msg)
    {
        return ::sendto(native_socket, reinterpret_cast<const char*>(msg.data()), msg.size(), MSG_CONFIRM,
                        reinterpret_cast<const sockaddr*>(&dest_address_info), sizeof(dest_address_info));
    }

    auto receive_from(::sockaddr_in& src_address_info, byte_span_t received_bytes)
    {
        auto received_address_obj_size = socklen_t{sizeof(src_address_info)};
        return ::recvfrom(native_socket, reinterpret_cast<char*>(received_bytes.data()), received_bytes.size(), 0,
                          reinterpret_cast<sockaddr*>(&src_address_info), &received_address_obj_size);
    }
};

} // namespace lichat::net