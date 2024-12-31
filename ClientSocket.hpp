#include "Bytes.hpp"
#include "Socket.hpp"

#include <chrono>
#include <utility>

namespace lichat::net {
class ClientSocket {
    ::sockaddr_in address_info{};
    socket_t      native_socket{INVALID_SOCKET_VALUE};
    SocketJanitor socket_janitor;

    [[nodiscard]] static auto set_socket_timeout(socket_t native_socket, std::chrono::milliseconds timeout)
    {
#ifdef _WIN32
        ::DWORD timeout_val = timeout.count();
#else
        ::timeval timeout_val;
        timeout.tv_sec  = std::chrono::duration_cast<std::chrono::seconds>(timeout).count();
        timeout.tv_usec = std::chrono::duration_cast<std::chrono::microseconds>(timeout).count() - 1'000'000 * timeout.tv_sec;
#endif

        return ::setsockopt(native_socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_val), sizeof(timeout_val));
    }

    [[nodiscard]] auto init_native_socket(socket_t native, ::sockaddr_in& address_info) -> SocketJanitor
    {
        if (native_socket == INVALID_SOCKET_VALUE) {
            throw SocketException{"Socket creation failed", SocketErrorCode::createSocketFailed};
        }

        auto socketCloser = SocketJanitor(native_socket);

        if (set_socket_timeout(native_socket, std::chrono::seconds{SERVER_RECV_WAIT_SECS}) == SOCKET_ERROR_VALUE) {
            throw SocketException{"Failed to set socket timeout", SocketErrorCode::setTimeoutFailed};
        }

        std::cout << "lichat client started. Handshaking now ..." << std::endl;

        return socketCloser;
    }

public:
    ClientSocket(const std::string& address, uint16_t port)
        : address_info{make_sockaddr_in(address, port)}
        , native_socket{::socket(AF_INET, SOCK_DGRAM, 0)}
        , socket_janitor{init_native_socket(native_socket, address_info)}
    {
    }

    [[nodiscard]] auto port() const noexcept -> uint16_t
    {
        return htons(address_info.sin_port);
    }

    auto set_timeout(std::chrono::microseconds timeout) {
        return set_socket_timeout(native_socket, std::chrono::seconds{HANDSHAKE_TIMEOUT_SECS});
    }

    [[nodiscard]] auto make_nonblocking() -> bool
    {
        return make_socket_nonblocking(native_socket);
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

    auto receive(byte_span_t received_bytes)
    {
        auto       src_address_info          = ::sockaddr_in{};
        auto       received_address_obj_size = socklen_t{sizeof(src_address_info)};
        auto const bytes_recv_count =
            static_cast<size_t>(std::max(0, ::recvfrom(native_socket, reinterpret_cast<char*>(received_bytes.data()), received_bytes.size(),
                                                       0, reinterpret_cast<sockaddr*>(&src_address_info), &received_address_obj_size)));

        return std::pair{byte_span_t{received_bytes.data(), bytes_recv_count}, src_address_info};
    }
};

} // namespace lichat::net