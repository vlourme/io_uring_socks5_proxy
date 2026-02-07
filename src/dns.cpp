#include <chrono>
#include <mutex>
#include <netinet/in.h>
#include <optional>
#include <shared_mutex>
#include <unordered_map>

struct CachedAddr {
    sockaddr_in6 addr;
    std::chrono::steady_clock::time_point expiry;
};

class DNSResolver {
    std::unordered_map<std::string, CachedAddr> cache;
    std::shared_mutex mtx;
    const std::chrono::seconds ttl{300}; // 5-minute cache

  public:
    // Check if we have a valid cached address
    std::optional<sockaddr_in6> get_cached(const std::string &host) {
        std::shared_lock lock(mtx);
        auto it = cache.find(host);
        if (it != cache.end() &&
            it->second.expiry > std::chrono::steady_clock::now()) {
            return it->second.addr;
        }
        return std::nullopt;
    }

    void update_cache(const std::string &host, sockaddr_in6 addr) {
        std::unique_lock lock(mtx);
        cache[host] = {addr, std::chrono::steady_clock::now() + ttl};
    }
};
