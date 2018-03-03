#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "dumbbox.h"

void init(void);
void target_handler(void);
void read_file(const char *filename);


int32_t main(int32_t argc, char **argv) {
    init();
    dumbbox_setup(target_handler);
    exit(EXIT_SUCCESS);
}


void target_handler(void) {
    int32_t fd;

    read_file("/tmp/testfile");
    read_file("/etc/passwd");
}

void read_file(const char *filename) {
    int32_t fd;
    char buf[513];
    fd = dumbbox_unpriv_open(filename, O_RDONLY);
    if (fd < 0) {
        printf("Error on opening file\n");
    }
    else {
        memset(buf, 0, sizeof(buf));
        read(fd, buf, sizeof(buf)-1);
        printf("%s", buf);
        close(fd);
    }

}

void init(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}
