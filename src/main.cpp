#include "dotenv.h"
#include "mimalloc.h"
#include <condy.hpp>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#include "dns.cpp"
#include "ipv6.cpp"
#include "pipe_pool.cpp"
#include "spdlog/spdlog.h"

constexpr int BACKLOG = 8096;
constexpr int RING_SIZE = 16 * 1024;

constexpr int SOCKS5_VERSION = 5;
constexpr char SOCKS5_ATYP_IPV4 = 1;
constexpr char SOCKS5_ATYP_DOMAIN = 3;
constexpr char SOCKS5_ATYP_IPV6 = 4;
constexpr char SOCKS5_NO_AUTH_RESPONSE[2] = {SOCKS5_VERSION, 0};
constexpr char SOCKS5_RESPONSE_OK[4] = {SOCKS5_VERSION, 0, 0, 4};
constexpr char SOCKS5_RESPONSE_DUMMY[18] = {0};

static thread_local PipePool local_pipe_pool;
static thread_local DNSResolver thread_local_resolver;

condy::Coro<sockaddr_in6> resolve_hostname(std::string hostname) {
    if (auto cached = thread_local_resolver.get_cached(hostname)) {
        co_return *cached;
    }

    addrinfo hints{};
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo *result = nullptr;
    if (getaddrinfo(hostname.c_str(), nullptr, &hints, &result) != 0) {
        co_return sockaddr_in6{};
    }

    sockaddr_in6 addr = *reinterpret_cast<sockaddr_in6 *>(result->ai_addr);
    freeaddrinfo(result);

    if (addr.sin6_family != 0) {
        thread_local_resolver.update_cache(hostname, addr);
    }

    co_return addr;
}

condy::Coro<int> read_port(int fd) {
    char port[2];
    co_await condy::async_recv(condy::fixed(fd), condy::buffer(port), 0);
    co_return ntohs(*(uint16_t *)port);
}

condy::Coro<std::tuple<std::string, int>> read_socks_address(int fd,
                                                             char atyp) {
    std::string address;

    switch (atyp) {
    case SOCKS5_ATYP_IPV4:
        co_return std::make_tuple("", 0);
    case SOCKS5_ATYP_DOMAIN:
        char length[1];
        co_await condy::async_recv(condy::fixed(fd), condy::buffer(length), 0);
        address = std::string(length[0], '\0');
        co_await condy::async_recv(condy::fixed(fd), condy::buffer(address), 0);
        break;
    case SOCKS5_ATYP_IPV6:
        unsigned char ipv6_bin[16];
        co_await condy::async_recv(condy::fixed(fd), condy::buffer(ipv6_bin),
                                   0);

        char ipv6_str[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, ipv6_bin, ipv6_str, sizeof(ipv6_str))) {
            address = ipv6_str;
        }
        break;
    }

    int port = co_await read_port(fd);
    co_return std::make_tuple(address, port);
}

condy::Coro<uint64_t> forward_one_way(int src, int dst, Pipe p) {
    uint64_t total_bytes = 0;
    while (true) {
        ssize_t received = co_await condy::async_splice(
            condy::fixed(src), -1, p.fds[1], -1, 128 * 1024,
            SPLICE_F_NONBLOCK | SPLICE_F_MOVE);

        if (received <= 0)
            break;

        ssize_t pending = received;
        while (pending > 0) {
            ssize_t sent = co_await condy::async_splice(
                p.fds[0], -1, condy::fixed(dst), -1, pending,
                SPLICE_F_NONBLOCK | SPLICE_F_MOVE);

            if (sent <= 0)
                co_return total_bytes;

            pending -= sent;
            total_bytes += sent;
        }
    }
    co_return total_bytes;
}

condy::Coro<uint64_t> proxy(int client_fd, int server_fd) {
    Pipe p1 = co_await local_pipe_pool.acquire();
    Pipe p2 = co_await local_pipe_pool.acquire();

    auto aw1 = condy::co_spawn(forward_one_way(client_fd, server_fd, p1));
    auto aw2 = condy::co_spawn(forward_one_way(server_fd, client_fd, p2));

    uint64_t total = co_await aw1 + co_await aw2;

    local_pipe_pool.release(p1);
    local_pipe_pool.release(p2);

    co_await condy::link(condy::async_close(condy::fixed(client_fd)),
                         condy::async_close(condy::fixed(server_fd)));

    spdlog::info("proxy total bytes: {} ({} -> {})", total, client_fd,
                 server_fd);

    co_return total;
}

condy::Coro<void> session(int fd, sockaddr_storage client_addr) {
    char ip_str[INET6_ADDRSTRLEN];
    auto ip = get_ip_str((sockaddr *)&client_addr, ip_str, sizeof(ip_str));

    if (!is_authorized(&client_addr)) {
        spdlog::warn("unauthorized access from {}", ip);
        co_await condy::async_close(fd);
        co_return;
    }

    int opt = 1;
    co_await condy::async_cmd_sock(SOCKET_URING_OP_SETSOCKOPT, condy::fixed(fd),
                                   IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    char version[2];
    co_await condy::async_recv(condy::fixed(fd), condy::buffer(version), 0);
    if (version[0] != SOCKS5_VERSION) {
        spdlog::error("[{}] invalid SOCKS5 version, expected: {}, got: {}", fd,
                      SOCKS5_VERSION, version[0]);
        co_await condy::async_close(fd);
        co_return;
    }

    char methods[255];
    char request[4];
    co_await condy::link(
        condy::async_recv(condy::fixed(fd), condy::buffer(methods), 0),
        condy::async_send(condy::fixed(fd),
                          condy::buffer(SOCKS5_NO_AUTH_RESPONSE), 0),
        condy::async_recv(condy::fixed(fd), condy::buffer(request), 0));

    if (request[1] != 1) {
        co_await condy::async_close(condy::fixed(fd));
        co_return;
    }

    auto [address, port] = co_await read_socks_address(fd, request[3]);
    if (address.empty() || port == 0) {
        spdlog::error("[{}] invalid SOCKS5 address, address: {}, port: {}", fd,
                      address, port);
        co_await condy::async_close(condy::fixed(fd));
        co_return;
    }

    sockaddr_in6 addr = co_await resolve_hostname(address);
    if (addr.sin6_family == 0) {
        co_await condy::async_close(condy::fixed(fd));
        co_return;
    }
    addr.sin6_port = htons(port);

    char outbound_addr[sizeof(sockaddr_in6)];
    generate_ip((sockaddr_in6 *)outbound_addr);

    int outbound_fd = co_await condy::async_socket_direct(
        AF_INET6, SOCK_STREAM, 0, CONDY_FILE_INDEX_ALLOC, 0);
    if (outbound_fd < 0) {
        co_await condy::async_close(condy::fixed(fd));
        co_return;
    }

    int r = co_await condy::async_cmd_sock(
        SOCKET_URING_OP_SETSOCKOPT, condy::fixed(outbound_fd), IPPROTO_IPV6,
        IPV6_FREEBIND, &opt, sizeof(opt));
    if (r < 0) {
        spdlog::error("[{}] failed to set socket option, error: {}", fd, r);
        co_await condy::when_any(condy::async_close(condy::fixed(outbound_fd)),
                                 condy::async_close(condy::fixed(fd)));
        co_return;
    }

    r = co_await condy::async_cmd_sock(SOCKET_URING_OP_SETSOCKOPT,
                                       condy::fixed(outbound_fd), IPPROTO_TCP,
                                       TCP_NODELAY, &opt, sizeof(opt));
    if (r < 0) {
        spdlog::error("[{}] failed to set socket option, error: {}", fd, r);
        co_await condy::when_any(condy::async_close(condy::fixed(outbound_fd)),
                                 condy::async_close(condy::fixed(fd)));
        co_return;
    }

    r = co_await condy::async_bind(condy::fixed(outbound_fd),
                                   (struct sockaddr *)&outbound_addr,
                                   sizeof(outbound_addr));
    if (r < 0) {
        spdlog::error("[{}] failed to bind socket, error: {}", fd,
                      strerror(errno));
        co_await condy::when_any(condy::async_close(condy::fixed(outbound_fd)),
                                 condy::async_close(condy::fixed(fd)));
        co_return;
    }

    r = co_await condy::async_connect(condy::fixed(outbound_fd),
                                      (struct sockaddr *)&addr, sizeof(addr));
    if (r < 0) {
        co_await condy::when_any(condy::async_close(condy::fixed(outbound_fd)),
                                 condy::async_close(condy::fixed(fd)));
        co_return;
    }

    co_await condy::link(
        condy::async_send(condy::fixed(fd), condy::buffer(SOCKS5_RESPONSE_OK),
                          0),
        condy::async_send(condy::fixed(fd),
                          condy::buffer(SOCKS5_RESPONSE_DUMMY), 0));

    condy::co_spawn(proxy(fd, outbound_fd)).detach();

    co_return;
}

condy::Coro<int> co_main(int core_id, int port) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

    condy::current_runtime().fd_table().init(BACKLOG);

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, "0.0.0.0", &server_addr.sin_addr);

    int server_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        spdlog::error("[{}] failed to create socket, error: {}", core_id,
                      strerror(errno));
        co_return 1;
    }
    spdlog::info("[{}] created socket, fd: {}", core_id, server_fd);

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    int r =
        ::bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (r < 0) {
        co_await condy::async_close(server_fd);
        spdlog::error("[{}] failed to bind socket, error: {}", core_id,
                      strerror(errno));
        co_return 1;
    }

    r = ::listen(server_fd, BACKLOG);
    if (r < 0) {
        co_await condy::async_close(server_fd);
        spdlog::error("[{}] failed to listen socket, error: {}", core_id,
                      strerror(errno));
        co_return 1;
    }

    spdlog::info("[{}] ready to accept connections on port {}", core_id, port);
    while (true) {
        sockaddr_storage client_addr{};
        socklen_t client_addr_len = sizeof(client_addr);
        int client_fd = co_await condy::async_accept_direct(
            server_fd, (struct sockaddr *)&client_addr, &client_addr_len, 0,
            CONDY_FILE_INDEX_ALLOC);
        if (client_fd < 0) {
            spdlog::error("[{}] failed to accept connection, error: {}",
                          core_id, strerror(errno));
            continue;
        }

        condy::co_spawn(session(client_fd, client_addr)).detach();
    }

    co_await condy::async_close(server_fd);

    mi_collect(true);

    co_return 0;
}

int main() {
    dotenv::init();

    std::string ipv6_prefix = dotenv::getenv("IPV6_PREFIXES");
    ipv6_prefixes = parse_multi_cidr(ipv6_prefix);

    std::string auth_list = dotenv::getenv("AUTH_LIST");
    load_auth_from_string(auth_list);

    auto port_str = dotenv::getenv("PORT");
    int port = 1080;
    if (port_str.empty()) {
        spdlog::info("No port specified, using default port 1080");
    } else {
        try {
            port = std::stoi(port_str);
            if (port <= 0 || port > 65535) {
                spdlog::error("Invalid port: {}", port_str);
                return 1;
            }
        } catch (const std::invalid_argument &e) {
            spdlog::error("Invalid port: {}", port_str);
            return 1;
        }
    }

    int num_cores = std::thread::hardware_concurrency();
    spdlog::info("Starting proxy on {} cores", num_cores);
    std::vector<std::thread> workers;

    for (int i = 0; i < num_cores; ++i) {
        workers.emplace_back([i, port]() {
            condy::Runtime runtime(
                condy::default_runtime_options().sq_size(RING_SIZE).cq_size(
                    RING_SIZE));
            auto t = condy::co_spawn(runtime, co_main(i, port));
            runtime.run();
            return t.wait();
        });
    }

    for (auto &t : workers)
        t.join();

    return 0;
}
