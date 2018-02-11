#ifndef SHA_1_SHA1_H
#define SHA_1_SHA1_H


#include <vector>
#include <cstdint>
#include <string>
#include <array>

#define CIRC_LEFT_SHIFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))            // Left circular shift


typedef uint8_t byte;

class SHA1
{
public:
    SHA1() = default;

    explicit SHA1(const std::string &line, bool _file = false);

    std::string generate();

private:
    void init();
    void readFile(std::vector<byte> &msg, const std::string &path);
    void writeFile(const std::string &msg, const std::string &path);

    uint F(uint j, uint x, uint y, uint z);

    std::vector<byte> data;
    std::array<uint, 5> h;
    std::array<uint, 4> k;
    bool file = false;
    std::string filePath = "";
};


#endif //SHA_1_SHA1_H
