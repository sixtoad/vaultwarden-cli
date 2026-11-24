#include <unistd.h>

int main(void) {
    if (write(STDOUT_FILENO, "R", 1) != 1) {
        return 1;
    }
    sleep(60);
    return 0;
}
