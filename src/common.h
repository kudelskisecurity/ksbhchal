#pragma once

#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdint.h>

void printbytes(const uint8_t *m, int len) {
	int i;
	for (i = 0; i < len-1; ++i)
		printf("%02x", m[i]);
	printf("%02x\n", m[len-1]);
}

int getkey(uint8_t *skseed) {
    int fd = open("./key", O_RDONLY);
    if (fd < 0) return 1;
    int r =read(fd, skseed, 32);
    close(fd);
    if (r != 32) return 1;
    return 0;
}