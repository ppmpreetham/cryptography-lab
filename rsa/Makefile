# Makefile – RSA Server & Client
CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11 -O2
OBJ     = rsa.o

.PHONY: all test clean

all: server client

rsa.o: rsa.c rsa.h
	$(CC) $(CFLAGS) -c rsa.c -o rsa.o

server: server.c $(OBJ) rsa.h
	$(CC) $(CFLAGS) server.c $(OBJ) -o server

client: client.c $(OBJ) rsa.h
	$(CC) $(CFLAGS) client.c $(OBJ) -o client

test: rsa_test
	./rsa_test

rsa_test: rsa_test.c $(OBJ) rsa.h
	$(CC) $(CFLAGS) rsa_test.c $(OBJ) -o rsa_test

clean:
	rm -f *.o server client rsa_test