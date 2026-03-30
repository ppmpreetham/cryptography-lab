CC      = gcc
CFLAGS  = -Wall -Wextra -Wpedantic -std=c11 -g
TARGETS = server client

.PHONY: all clean run-server run-client

all: $(TARGETS)

server: server.c elgamal.h protocol.h
	$(CC) $(CFLAGS) -o $@ $<

client: client.c elgamal.h protocol.h
	$(CC) $(CFLAGS) -o $@ $<

run-server: server
	./server

run-client: client
	./client 127.0.0.1

clean:
	rm -f $(TARGETS)
