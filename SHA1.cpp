#include <ios>
#include <iomanip>
#include <sstream>
#include <fstream>
#include "SHA1.h"

SHA1::SHA1(const std::string &line, bool _file)
{
    if (_file)
    {
        readFile(data, line);
        file = true;
        filePath += line;
    } else
    {
        for (byte ch : line)
        {
            data.push_back(ch);         // Transform string to vector
        }
    }

    ulong srcBitLen = data.size() * 8;

    // Extend the message
    data.push_back((byte) 0x80);    // Add 1 bit

    while ((data.size() * 8) % 512 != 448)
    {
        data.push_back(0);          // Add zeroes until length of message is not 448 mod 512
    }

    // Add the message length
    ulong len = data.size();
    data.resize(len + 8);

    for (ulong i = data.size() - 1; i >= len; i--)
    {
        data[i] = (byte) srcBitLen;
        srcBitLen >>= 8;
    }

    this->init();
}

void SHA1::init()
{
    h[0] = 0x67452301;
    h[1] = 0xEFCDAB89;
    h[2] = 0x98BADCFE;
    h[3] = 0x10325476;
    h[4] = 0xC3D2E1F0;

    k[0] = 0x5A827999;
    k[1] = 0x6ED9EBA1;
    k[2] = 0x8F1BBCDC;
    k[3] = 0xCA62C1D6;
}

std::string SHA1::generate()
{
    for (uint i = 0; i < data.size(); i += 64)      // Go through 64 bit blocks
    {
        uint temp;
        std::vector<byte> block(64);
        std::move(data.begin() + i, data.begin() + i + 64, block.begin());

        std::vector<uint> word(80);
        for (uint j = 0; j < 16; ++j)               // Convert to big-endian and store first 16
        {
            word[j] =
                    ((uint) block[j * 4 + 0] << 24) |
                    ((uint) block[j * 4 + 1] << 16) |
                    ((uint) block[j * 4 + 2] << 8) |
                    ((uint) block[j * 4 + 3] << 0);
        }

        for (uint j = 16; j < 80; ++j)              // 64 elements calculated using circular shift
        {
            word[j] = CIRC_LEFT_SHIFT((word[j - 3] ^ word[j - 8] ^ word[j - 14] ^ word[j - 16]), 1);
        }
        uint a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];


        for (uint j = 0; j < 80; ++j)
        {
            temp = CIRC_LEFT_SHIFT(a, 5) + F(j, b, c, d) + e + word[j] + k[j / 20];
            e = d;
            d = c;
            c = CIRC_LEFT_SHIFT(b, 30);
            b = a;
            a = temp;
        }

        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
    }


    std::ostringstream result;

    for (auto &hash : h)
    {
        result << std::hex << std::setfill('0') << std::setw(8) << hash << " ";
    }

    if (file)
    {
        writeFile(result.str(), filePath + "_hash");
    }

    return result.str();
}

uint SHA1::F(uint j, uint x, uint y, uint z)
{
    if (j < 20)
        return (x & y) | ((~x) & z);
    else if (j < 40)
        return x ^ y ^ z;
    else if (j < 60)
        return (x & y) | (x & z) | (y & z);
    else if (j < 80)
        return x ^ y ^ z;
    else
        return 0;
}

void SHA1::readFile(std::vector<byte> &msg, const std::string &path)
{
    FILE *f = fopen(path.c_str(), "rb");
    int c;

    while ((c = getc(f)) != EOF)
    {
        msg.push_back((byte) c);
    }
}

void SHA1::writeFile(const std::string &msg, const std::string &path)
{
    std::ofstream out(path);

    for (auto b : msg)
    {
        out << b;
    }

    out.close();
}