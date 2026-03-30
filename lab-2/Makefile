CC = gcc
CFLAGS = -Wall -Wextra -lm

# Weak system executables
WEAK_SERVER = server_weak
WEAK_CLIENT = client_weak

# Secure system executables
SECURE_SERVER = server_secure
SECURE_CLIENT = client_secure

# Attack executables
ATTACKER_GCD = attacker_gcd
ATTACKER_REPLAY = attacker_replay
ATTACKER_PREDICT = attacker_predict
ATTACKER_IMPERSON = attacker_imperson
ATTACKER_FAIL = attacker_fail_secure

# All targets
all: weak secure attacks

weak: $(WEAK_SERVER) $(WEAK_CLIENT)

secure: $(SECURE_SERVER) $(SECURE_CLIENT)

attacks: $(ATTACKER_GCD) $(ATTACKER_REPLAY) $(ATTACKER_PREDICT) $(ATTACKER_IMPERSON) $(ATTACKER_FAIL)

# Weak system compilation
$(WEAK_SERVER): server_weak.c
	$(CC) $(CFLAGS) -o $(WEAK_SERVER) server_weak.c

$(WEAK_CLIENT): client_weak.c
	$(CC) $(CFLAGS) -o $(WEAK_CLIENT) client_weak.c

# Secure system compilation
$(SECURE_SERVER): server_secure.c
	$(CC) $(CFLAGS) -o $(SECURE_SERVER) server_secure.c

$(SECURE_CLIENT): client_secure.c
	$(CC) $(CFLAGS) -o $(SECURE_CLIENT) client_secure.c

# Attack tools compilation
$(ATTACKER_GCD): attacker_gcd.c
	$(CC) $(CFLAGS) -o $(ATTACKER_GCD) attacker_gcd.c

$(ATTACKER_REPLAY): attacker_replay.c
	$(CC) $(CFLAGS) -o $(ATTACKER_REPLAY) attacker_replay.c

$(ATTACKER_PREDICT): attacker_predict.c
	$(CC) $(CFLAGS) -o $(ATTACKER_PREDICT) attacker_predict.c

$(ATTACKER_IMPERSON): attacker_imperson.c
	$(CC) $(CFLAGS) -o $(ATTACKER_IMPERSON) attacker_imperson.c

$(ATTACKER_FAIL): attacker_fail_secure.c
	$(CC) $(CFLAGS) -o $(ATTACKER_FAIL) attacker_fail_secure.c

# Clean compiled files
clean:
	rm -f $(WEAK_SERVER) $(WEAK_CLIENT) $(SECURE_SERVER) $(SECURE_CLIENT) \
	      $(ATTACKER_GCD) $(ATTACKER_REPLAY) $(ATTACKER_PREDICT) \
	      $(ATTACKER_IMPERSON) $(ATTACKER_FAIL)

# Generate graphs
graphs:
	python3 plot_graphs.py

# Help target
help:
	@echo "Available targets:"
	@echo "  make all        - Compile everything"
	@echo "  make weak       - Compile weak system only"
	@echo "  make secure     - Compile secure system only"
	@echo "  make attacks    - Compile attack tools only"
	@echo "  make graphs     - Generate all graphs"
	@echo "  make clean      - Remove all compiled files"
	@echo ""
	@echo "Testing sequences:"
	@echo "  1. Test weak system:"
	@echo "     Terminal 1: ./server_weak"
	@echo "     Terminal 2: ./client_weak 2"
	@echo "     Terminal 3: ./attacker_gcd"
	@echo "     Terminal 4: ./attacker_replay"
	@echo "     Terminal 5: ./attacker_predict"
	@echo "     Terminal 6: ./attacker_imperson"
	@echo ""
	@echo "  2. Test secure system:"
	@echo "     Terminal 1: ./server_secure"
	@echo "     Terminal 2: ./client_secure 5"
	@echo "     Terminal 3: ./attacker_fail_secure"

.PHONY: all weak secure attacks clean graphs help