#include <stdio.h>
#include <string.h>

static int greet(const char *name)
{
    char buf[16];
    if (strlen(name) >= sizeof buf) {
        fprintf(stderr, "name too long\n");
        return 2;
    }
    strcpy(buf, name);
    printf("hello %s\n", buf);
    return 0;
}

int main(void)
{
    char line[256];
    if (!fgets(line, sizeof line, stdin)) {
        fprintf(stderr, "usage: echo NAME | greet\n");
        return 1;
    }
    line[strcspn(line, "\n")] = 0;
    if (line[0] == 0) {
        fprintf(stderr, "empty name\n");
        return 1;
    }
    return greet(line);
}
