CFLAGS=-std=c99 -Wno-format -march=native -funroll-loops -fomit-frame-pointer -O3 -fsanitize=address


sign:   *.c *.h Makefile
	$(CC) $(CFLAGS) hors.c haraka.c sign.c -o sign
	
clean:
	rm -f sign
