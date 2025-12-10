#pragma once
#include <array>
#include <cstdint>
#include <string>

class SHA256 {
public:
    SHA256();
    void update(const uint8_t *data, size_t length);
    void update(const std::string &data);
    std::string final();
    static std::string fromFile(const std::string &path);

private:
    void transform(const uint8_t *chunk);

    uint64_t bitLength;
    std::array<uint8_t, 64> buffer;
    size_t bufferLength;
    std::array<uint32_t, 8> state;
};

