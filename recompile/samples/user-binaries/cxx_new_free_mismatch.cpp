#include <cstdlib>

int main() {
    int *value = new int(7);
    std::free(value);
    return 0;
}
