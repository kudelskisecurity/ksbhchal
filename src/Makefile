CFLAGS=-std=c99 -O3 -Wno-format -march=native -funroll-loops -fomit-frame-pointer


sign:   *.c *.h
	$(CC) $(CFLAGS) hors.c haraka.c sign.c -o sign
	
clean:
	rm haraka
