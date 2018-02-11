#include <iostream>
#include <cstring>
#include "SHA1.h"

int main(int argc, char **argv)
{
    bool file = false;
    if (std::strcmp(argv[1], "-s") == 0)
    {
        file = false;
    } else if (std::strcmp(argv[1], "-f") == 0)
    {
        file = true;
    } else
    {
        std::cout << "Please, use flag -s/-f to hash string/file";
        return 1;
    }
    if (!file)
    {
        std::cout << SHA1(argv[2]).generate();
    } else
    {
        std::cout << SHA1(argv[2], true).generate();
    }


    return 0;
}