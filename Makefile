CFLAGS=-std=c99 -Wno-format -march=native -funroll-loops -fomit-frame-pointer -O3 -fsanitize=address

sign:   src/haraka.c src/hors.c src/sign.c
		$(CC) $(CFLAGS) $^ -o $@
	
verify: src/haraka.c src/hors.c src/verify.c
		$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -f sign verify