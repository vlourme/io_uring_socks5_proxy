#include <condy.hpp>
#include <fcntl.h>
#include <vector>

struct Pipe {
    int fds[2];
};

class PipePool {
    std::vector<Pipe> pool;

  public:
    condy::Coro<Pipe> acquire() {
        if (pool.empty()) {
            int p[2];
            if (co_await condy::async_pipe(p, O_NONBLOCK | O_CLOEXEC) < 0)
                co_return {-1, -1};
            fcntl(p[0], F_SETPIPE_SZ, 128 * 1024);
            fcntl(p[1], F_SETPIPE_SZ, 128 * 1024);
            co_return {p[0], p[1]};
        }
        Pipe p = pool.back();
        pool.pop_back();
        co_return p;
    }

    void release(Pipe p) { pool.push_back(p); }
};