CFLAGS=-std=c99 -O3 -Wno-format -march=native -fomit-frame-pointer

all:	sign verify hash

sign:   src/haraka.c src/hors.c src/sign.c
		$(CC) $(CFLAGS) $^ -o $@
	
verify: src/haraka.c src/hors.c src/verify.c
		$(CC) $(CFLAGS) $^ -o $@

hash: 	src/haraka.c src/hash.c
		$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -f sign verify hash *.dSYM
