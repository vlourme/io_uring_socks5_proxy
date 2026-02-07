#include <arpa/inet.h>
#include <cstring>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

struct OutboundPrefix {
    uint64_t net_high;       // Network part (high 64 bits)
    uint64_t net_low;        // Network part (low 64 bits)
    uint64_t host_mask_high; // Bits available for randomization (high)
    uint64_t host_mask_low;  // Bits available for randomization (low)
};

std::vector<OutboundPrefix> parse_multi_cidr(const std::string &input) {
    std::vector<OutboundPrefix> prefixes;
    std::stringstream ss(input);
    std::string item;

    while (std::getline(ss, item, ',')) {
        // Remove potential whitespace
        item.erase(0, item.find_first_not_of(" "));
        item.erase(item.find_last_not_of(" ") + 1);

        size_t slash = item.find('/');
        if (slash == std::string::npos)
            continue;

        std::string ip_str = item.substr(0, slash);
        int len = std::stoi(item.substr(slash + 1));

        in6_addr addr;
        if (inet_pton(AF_INET6, ip_str.c_str(), &addr) != 1)
            continue;

        OutboundPrefix p;
        // Load bytes into 64-bit integers in Host Byte Order for easy math
        uint64_t high, low;
        std::memcpy(&high, &addr.s6_addr[0], 8);
        std::memcpy(&low, &addr.s6_addr[8], 8);
        high = __builtin_bswap64(high);
        low = __builtin_bswap64(low);

        // Calculate masks based on prefix length
        if (len == 0) {
            p.host_mask_high = ~0ULL;
            p.host_mask_low = ~0ULL;
        } else if (len <= 64) {
            p.host_mask_high = (len == 64) ? 0 : (~0ULL >> len);
            p.host_mask_low = ~0ULL;
        } else {
            p.host_mask_high = 0;
            p.host_mask_low = (len == 128) ? 0 : (~0ULL >> (len - 64));
        }

        // Clean the network part (zero out any bits in the host area)
        p.net_high = high & ~p.host_mask_high;
        p.net_low = low & ~p.host_mask_low;

        prefixes.push_back(p);
    }
    return prefixes;
}

static std::vector<OutboundPrefix> ipv6_prefixes;

inline void generate_ip(sockaddr_in6 *out) {
    const auto &p = ipv6_prefixes[rand() % ipv6_prefixes.size()];
    static thread_local uint64_t state = 0x12345678; // Fast PRNG seed
    auto fast_rand = []() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        return state;
    };

    uint64_t r_high = p.net_high | (fast_rand() & p.host_mask_high);
    uint64_t r_low = p.net_low | (fast_rand() & p.host_mask_low);

    r_high = __builtin_bswap64(r_high);
    r_low = __builtin_bswap64(r_low);

    out->sin6_family = AF_INET6;
    std::memcpy(&out->sin6_addr.s6_addr[0], &r_high, 8);
    std::memcpy(&out->sin6_addr.s6_addr[8], &r_low, 8);
}

// Fast hash for IPv4 (it's just a 32-bit uint)
struct IPv4Hash {
    size_t operator()(const in_addr &addr) const {
        return static_cast<size_t>(addr.s_addr);
    }
};

struct IPv4Equal {
    bool operator()(const in_addr &a, const in_addr &b) const {
        return a.s_addr == b.s_addr;
    }
};

// Reuse the IPv6 helpers from before...
struct IPv6Hash {
    size_t operator()(const in6_addr &addr) const {
        const uint64_t *p = reinterpret_cast<const uint64_t *>(&addr);
        return p[0] ^ p[1];
    }
};

struct IPv6Equal {
    bool operator()(const in6_addr &a, const in6_addr &b) const {
        return std::memcmp(&a, &b, 16) == 0;
    }
};

static std::unordered_set<in_addr, IPv4Hash, IPv4Equal> g_auth_v4;
static std::unordered_set<in6_addr, IPv6Hash, IPv6Equal> g_auth_v6;

bool is_authorized(const sockaddr_storage *addr) {
    if (addr->ss_family == AF_INET) {
        const auto *sin = reinterpret_cast<const sockaddr_in *>(addr);
        return g_auth_v4.contains(sin->sin_addr);
    }
    if (addr->ss_family == AF_INET6) {
        const auto *sin6 = reinterpret_cast<const sockaddr_in6 *>(addr);

        if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
            in_addr v4;
            memcpy(&v4, &sin6->sin6_addr.s6_addr[12], 4);
            return g_auth_v4.contains(v4);
        }
        return g_auth_v6.contains(sin6->sin6_addr);
    }
    return false;
}

void load_auth_from_string(const std::string &list) {
    std::stringstream ss(list);
    std::string item;
    while (std::getline(ss, item, ',')) {
        in_addr v4;
        in6_addr v6;
        if (inet_pton(AF_INET, item.c_str(), &v4) == 1) {
            g_auth_v4.insert(v4);
        } else if (inet_pton(AF_INET6, item.c_str(), &v6) == 1) {
            g_auth_v6.insert(v6);
        }
    }
}

char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen) {
    const char *result = nullptr;
    if (sa->sa_family == AF_INET) {
        result = inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr), s,
                           maxlen);
    } else if (sa->sa_family == AF_INET6) {
        result = inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
                           s, maxlen);
    }

    if (result == nullptr) {
        strncpy(s, "Invalid/Unknown", maxlen);
        return s; // Return the buffer, not NULL, to keep spdlog happy
    }
    return s;
}