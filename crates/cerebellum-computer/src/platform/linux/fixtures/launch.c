#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

static int equals(const char *actual, const char *expected) {
    return actual && strcmp(actual, expected) == 0;
}

int main(int argc, char **argv) {
    if (argc == 2 && equals(argv[1], "crash")) {
        const struct rlimit no_core = {0, 0};
        if (setrlimit(RLIMIT_CORE, &no_core) != 0) return 70;
        raise(SIGSEGV);
        return 71;
    }
    if (argc == 2 && equals(argv[1], "exit")) return 0;
    if (argc != 3 || !equals(argv[1], "check") || !equals(argv[2], "%") ||
        !equals(getenv("PATH"), "/usr/bin:/bin") ||
        !equals(getenv("XDG_CURRENT_DESKTOP"), "LaunchFixture") ||
        !equals(getenv("XMODIFIERS"), "@im=launch-fixture") || getenv("LD_PRELOAD")) return 72;
    FILE *marker = fopen("/mnt/ck-launch-fixture/ran", "w");
    if (!marker) return 73;
    fclose(marker);
    sleep(4);
    return 0;
}
