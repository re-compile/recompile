#include <cstring>

int main() {
    auto *buffer = new char[32];
    std::memset(buffer, 0x41, 32);
    delete[] buffer;

    auto *value = new int(7);
    delete value;
    return 0;
}
