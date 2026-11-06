#include <stdio.h>
#include <unistd.h>

int main(void) {
    printf("[TARGET] Hello from sandboxed process (PID: %d, UID: %d)\n", getpid(), getuid());
    return 0;
}
