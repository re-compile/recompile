#include <cstdlib>

int main() {
    int *value = static_cast<int *>(std::malloc(sizeof(int)));
    if (!value) {
        return 1;
    }
    delete value;
    return 0;
}
