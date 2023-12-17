#include <iostream>
#include <memory>
#include "hwidex.h"

int main() {
    std::unique_ptr<Hashes> hash = HWID::GetHWID();
    std::cout << "\ncpu: " << hash->cpu << "\n";
    std::cout << "hdd: " << hash->hdd << "\n";
    std::cout << "sys: " << hash->sys  << "\n";
    std::cout << "all: " << hash->all << "\n";
}