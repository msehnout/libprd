build: test-rlib.c
	gcc test-rlib.c -o test-rlib rlibprd/target/release/librlibprd.a -lunbound -lssl -lcrypto -lpthread -ldl

test: build
	./test-rlib
