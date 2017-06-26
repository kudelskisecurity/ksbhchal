CFLAGS=-std=c99 -O3 -Wno-format -march=native -fomit-frame-pointer
CFLAGS_DEBUG=-std=c99 -O0 -Wno-format -march=native -g

all:	sign verify hash

sign:   src/haraka.c src/hors.c src/sign.c
		$(CC) $(CFLAGS) $^ -o $@

sign_debug:     src/haraka.c src/hors.c src/sign.c
		$(CC) $(CFLAGS_DEBUG) $^ -o $@
	
verify:         src/haraka.c src/hors.c src/verify.c
		$(CC) $(CFLAGS) $^ -o $@

verify_debug:   src/haraka.c src/hors.c src/verify.c
		$(CC) $(CFLAGS_DEBUG) $^ -o $@

hash: 	src/haraka.c src/hash.c
		$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -rf sign sign_debug verify verify_debug hash *.dSYM
