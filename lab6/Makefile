# ============================================================
#  Diffie-Hellman Demo — Makefile
# ============================================================
CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=c11 -D_GNU_SOURCE
LDFLAGS = -lm

.PHONY: all clean run

all: dh_server dh_client dh_attacker

dh_server: dh_server.c dh_common.h
    $(CC) $(CFLAGS) -o dh_server dh_server.c $(LDFLAGS) -lpthread
    @echo "✔ Built dh_server"

dh_client: dh_client.c dh_common.h
    $(CC) $(CFLAGS) -o dh_client dh_client.c $(LDFLAGS) -lpthread
    @echo "✔ Built dh_client"

dh_attacker: dh_attacker.c dh_common.h
    $(CC) $(CFLAGS) -o dh_attacker dh_attacker.c $(LDFLAGS) -lpthread
    @echo "✔ Built dh_attacker"

run: all
	@echo "Starting server in background..."
	./dh_server &
	@sleep 0.3
	./dh_client

graphs:
	pip install matplotlib numpy --quiet
	python3 dh_graphs.py
	@echo "✔ Graph saved: dh_visualization.png"

clean:
	rm -f dh_server dh_client dh_stats.csv