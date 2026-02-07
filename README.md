# io_uring socks5

Experimental SOCKS5 proxy written in C++ using liburing and Condy runtime.

## Building

```bash
git submodule update --init --recursive
cd third_party/condy/third_party/liburing
git checkout liburing-2.13
cd -
cmake -S . -B build
cmake --build build -j4 --config Release
cp .env.example .env
./build/proxy
```

## Dependencies

- [condy](https://github.com/wokron/condy)
- [spdlog](https://github.com/gabime/spdlog)
- [cpp-dotenv](https://github.com/adeharo9/cpp-dotenv/)
- [mimalloc](https://github.com/microsoft/mimalloc)