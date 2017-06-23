all:
	$(CC) fsidbg.c -o fsidbg

.PHONY: clean
clean:
	rm fsidbg
