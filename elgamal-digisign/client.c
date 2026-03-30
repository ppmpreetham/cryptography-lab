/*
 * client.c — ElGamal Signature Interactive Client
 *
 * Fully interactive: choose your own p, g, x (or auto-generate),
 * supply your own k (or randomise), type any messages, run tamper
 * experiments, and verify locally before sending to the server.
 *
 * Build:  gcc -Wall -Wextra -o client client.c
 * Run:    ./client [server_ip]     (default: 127.0.0.1)
 */

#include "protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

/* ══════════════════════════════════════════════════════════════════════════
 *  UI helpers
 * ══════════════════════════════════════════════════════════════════════════ */

#define CLR_RESET  "\033[0m"
#define CLR_BOLD   "\033[1m"
#define CLR_DIM    "\033[2m"
#define CLR_GREEN  "\033[32m"
#define CLR_RED    "\033[31m"
#define CLR_CYAN   "\033[36m"
#define CLR_YELLOW "\033[33m"

static void print_banner(void) {
    puts("\n" CLR_CYAN
         "╔══════════════════════════════════════════════════╗\n"
         "║   ElGamal Digital Signature — SIGNING CLIENT    ║\n"
         "╚══════════════════════════════════════════════════╝"
         CLR_RESET);
}

static void print_section(const char *title) {
    printf(CLR_BOLD "\n  ── %s " CLR_DIM, title);
    int pad = 44 - (int)strlen(title);
    for (int i = 0; i < pad; ++i) putchar('-');
    puts(CLR_RESET);
}

static void print_ok(const char *msg)   { printf(CLR_GREEN  "  ✓  %s\n" CLR_RESET, msg); }
static void print_err(const char *msg)  { printf(CLR_RED    "  ✗  %s\n" CLR_RESET, msg); }
static void print_warn(const char *msg) { printf(CLR_YELLOW "  !  %s\n" CLR_RESET, msg); }
static void print_hint(const char *msg) { printf(CLR_DIM    "     %s\n" CLR_RESET, msg); }

/* ══════════════════════════════════════════════════════════════════════════
 *  Input helpers
 * ══════════════════════════════════════════════════════════════════════════ */

/* Read a trimmed line into buf (max len). Returns 0 on EOF, 1 otherwise. */
static int read_line(const char *prompt, char *buf, int len) {
    printf(CLR_CYAN "  > " CLR_RESET "%s", prompt);
    fflush(stdout);
    if (!fgets(buf, len, stdin)) return 0;
    buf[strcspn(buf, "\n")] = '\0';
    return 1;
}

/* Prompt for an unsigned 64-bit integer; returns default_val on empty. */
static uint64_t prompt_u64(const char *label, uint64_t default_val) {
    char buf[64];
    printf(CLR_CYAN "  > " CLR_RESET "%s [default: %llu]: ",
           label, (unsigned long long)default_val);
    fflush(stdout);
    if (!fgets(buf, sizeof(buf), stdin)) return default_val;
    buf[strcspn(buf, "\n")] = '\0';
    if (buf[0] == '\0') return default_val;
    char *end;
    uint64_t v = (uint64_t)strtoull(buf, &end, 10);
    if (*end != '\0') { print_err("Not a valid number, using default."); return default_val; }
    return v;
}

/* Prompt for a single character choice from a set (e.g. "yn"). */
static char prompt_choice(const char *label, const char *choices) {
    char buf[16];
    while (1) {
        printf(CLR_CYAN "  > " CLR_RESET "%s [%s]: ", label, choices);
        fflush(stdout);
        if (!fgets(buf, sizeof(buf), stdin)) return choices[0];
        char c = (char)tolower((unsigned char)buf[0]);
        if (strchr(choices, c)) return c;
        printf("     Please enter one of: %s\n", choices);
    }
}

/* ══════════════════════════════════════════════════════════════════════════
 *  Key setup
 * ══════════════════════════════════════════════════════════════════════════ */

static void setup_keys(PrivateKey *priv, PublicKey *pub) {
    print_section("Key Setup");
    puts("");
    print_hint("ElGamal parameters: prime p, generator g (primitive root of p),");
    print_hint("and private key x where 1 < x < p-1.");
    puts("");

    char mode = prompt_choice("Key mode — (a)uto-generate or (m)anual", "am");

    if (mode == 'a') {
        /* ── Auto ── */
        uint64_t p = prompt_u64("Prime p", DEFAULT_PRIME_P);
        uint64_t g = prompt_u64("Generator g (primitive root of p)", DEFAULT_GENERATOR_G);

        /* Validate before proceeding */
        if (!is_prime(p)) {
            print_err("p is not prime — falling back to defaults.");
            p = DEFAULT_PRIME_P; g = DEFAULT_GENERATOR_G;
        } else if (!is_primitive_root(g, p)) {
            print_err("g is not a primitive root of p — falling back to defaults.");
            p = DEFAULT_PRIME_P; g = DEFAULT_GENERATOR_G;
        }

        elgamal_keygen(priv, pub, p, g);
        printf("  Private key  x = %llu  " CLR_DIM "(auto-generated)\n" CLR_RESET,
               (unsigned long long)priv->x);

    } else {
        /* ── Manual ── */
        puts("");
        print_hint("Tip: try p=23, g=5, x=6  (classic textbook example)");
        puts("");

        uint64_t p, g, x;
        while (1) {
            p = prompt_u64("Prime p", DEFAULT_PRIME_P);
            g = prompt_u64("Generator g (primitive root of p)", DEFAULT_GENERATOR_G);
            x = prompt_u64("Private key x  (must be 1 < x < p-1)", 6);

            int rc = elgamal_keygen_manual(priv, pub, p, g, x);
            if      (rc == -1) print_err("p is not prime. Try again.");
            else if (rc == -2) print_err("g is not a primitive root of p. Try again.");
            else if (rc == -3) { printf(CLR_RED "  ✗  x must satisfy 1 < x < %llu. Try again.\n" CLR_RESET,
                                        (unsigned long long)(p - 1)); }
            else break; /* all good */
        }
    }

    puts("");
    print_public_key(pub);
    printf("  Private key  x = %llu\n", (unsigned long long)priv->x);
    printf("  Hash of \"test\" mod (p-1) = %llu  " CLR_DIM "(sample)\n" CLR_RESET,
           (unsigned long long)hash_message("test", pub->p - 1));
}

/* ══════════════════════════════════════════════════════════════════════════
 *  Sign & send
 * ══════════════════════════════════════════════════════════════════════════ */

static void do_sign_and_send(int fd, const PrivateKey *priv, const PublicKey *pub) {
    print_section("Sign & Send a Message");

    char msg[MAX_MSG_LEN];
    if (!read_line("Message to sign: ", msg, sizeof(msg))) return;
    if (msg[0] == '\0') { print_warn("Empty message skipped."); return; }

    /* Optional: let user supply k */
    uint64_t k_override = 0;
    char ck = prompt_choice("Choose ephemeral k — (r)andom or (m)anual", "rm");
    if (ck == 'm') {
        k_override = prompt_u64("Ephemeral k  (must satisfy gcd(k, p-1)=1)", 0);
        if (k_override == 0) { print_err("k cannot be 0, using random."); k_override = 0; }
    }

    Signature sig;
    if (elgamal_sign(msg, priv, &sig, k_override) < 0) {
        print_err("Signing failed — k may have invalid gcd with p-1. Try a different k.");
        return;
    }

    printf("\n  Signing    : \"%s\"\n", msg);
    print_signature(&sig);

    /* Local verify before sending */
    int local_ok = elgamal_verify(msg, &sig, pub);
    if (local_ok) print_ok("Local verification passed — sending to server");
    else          print_err("Local verification FAILED — sending anyway for demo");

    SignedMessage sm;
    memset(&sm, 0, sizeof(sm));
    strncpy(sm.message, msg, MAX_MSG_LEN - 1);
    sm.sig = sig;
    sm.pub = *pub;

    if (send_signed_message(fd, &sm) < 0) print_err("Network send failed.");
    else                                   puts("  Status     : → sent to server\n");
}

/* ══════════════════════════════════════════════════════════════════════════
 *  Tamper experiment
 * ══════════════════════════════════════════════════════════════════════════ */

static void do_tamper(int fd, const PrivateKey *priv, const PublicKey *pub) {
    print_section("Tamper Experiment");
    print_hint("Sign one message, then substitute a different payload.");
    print_hint("The server should reject the tampered signature.\n");

    char real_msg[MAX_MSG_LEN], fake_msg[MAX_MSG_LEN];
    if (!read_line("Message to SIGN  (real): ", real_msg, sizeof(real_msg))) return;
    if (!read_line("Message to SEND  (fake): ", fake_msg, sizeof(fake_msg))) return;

    uint64_t k_override = 0;
    char ck = prompt_choice("Choose ephemeral k — (r)andom or (m)anual", "rm");
    if (ck == 'm') k_override = prompt_u64("Ephemeral k", 0);

    Signature sig;
    if (elgamal_sign(real_msg, priv, &sig, k_override) < 0) {
        print_err("Signing failed."); return;
    }

    printf("\n  Signed     : \"%s\"\n", real_msg);
    printf("  Sending    : \"%s\"\n",  fake_msg);
    print_signature(&sig);

    int tamper_verify = elgamal_verify(fake_msg, &sig, pub);
    if (tamper_verify)
        print_warn("Surprisingly, local tamper check passed (hash collision with these params).");
    else
        print_ok("Local tamper check: signature correctly does NOT match fake message.");

    SignedMessage sm;
    memset(&sm, 0, sizeof(sm));
    strncpy(sm.message, fake_msg, MAX_MSG_LEN - 1);
    sm.sig = sig;
    sm.pub = *pub;

    if (send_signed_message(fd, &sm) < 0) print_err("Network send failed.");
    else                                   puts("  Status     : → tampered message sent to server\n");
}

/* ══════════════════════════════════════════════════════════════════════════
 *  Manual verify (no network)
 * ══════════════════════════════════════════════════════════════════════════ */

static void do_manual_verify(const PublicKey *pub) {
    print_section("Manual Verify (offline)");
    print_hint("Enter a message and its signature (r, s) to verify locally.\n");

    char msg[MAX_MSG_LEN];
    if (!read_line("Message: ", msg, sizeof(msg))) return;

    Signature sig;
    sig.r = prompt_u64("Signature r", 0);
    sig.s = prompt_u64("Signature s", 0);

    int ok = elgamal_verify(msg, &sig, pub);
    puts("");
    if (ok) print_ok("SIGNATURE VALID — message is authentic.");
    else    print_err("SIGNATURE INVALID — message rejected.");
    puts("");
}

/* ══════════════════════════════════════════════════════════════════════════
 *  Show current keys
 * ══════════════════════════════════════════════════════════════════════════ */

static void do_show_keys(const PrivateKey *priv, const PublicKey *pub) {
    print_section("Current Keys");
    puts("");
    print_public_key(pub);
    printf("  Private key  x = %llu\n\n", (unsigned long long)priv->x);
}

/* ══════════════════════════════════════════════════════════════════════════
 *  Main menu
 * ══════════════════════════════════════════════════════════════════════════ */

static void print_menu(void) {
    puts(CLR_BOLD "\n  ┌──────────────────────────────────────────────┐" CLR_RESET);
    puts(CLR_BOLD "  │  What would you like to do?                  │" CLR_RESET);
    puts(CLR_BOLD "  ├──────────────────────────────────────────────┤" CLR_RESET);
    puts("  │  [1]  Sign & send a message                  │");
    puts("  │  [2]  Tamper experiment                       │");
    puts("  │  [3]  Verify a signature locally (offline)   │");
    puts("  │  [4]  Regenerate / change keys               │");
    puts("  │  [5]  Show current keys                      │");
    puts("  │  [q]  Quit                                    │");
    puts(CLR_BOLD "  └──────────────────────────────────────────────┘" CLR_RESET);
}

/* ══════════════════════════════════════════════════════════════════════════
 *  Entry point
 * ══════════════════════════════════════════════════════════════════════════ */

int main(int argc, char *argv[]) {
    const char *host = (argc > 1) ? argv[1] : "127.0.0.1";

    print_banner();
    printf("  Connecting to %s:%d …\n", host, SOCKET_PORT);

    int fd = create_client_socket(host, SOCKET_PORT);
    if (fd < 0) { perror("create_client_socket"); return EXIT_FAILURE; }
    print_ok("Connected!\n");

    srand((unsigned)time(NULL));

    PublicKey  pub;
    PrivateKey priv;
    setup_keys(&priv, &pub);

    char choice[8];
    for (;;) {
        print_menu();
        if (!read_line("Choice: ", choice, sizeof(choice))) break;

        switch (choice[0]) {
            case '1': do_sign_and_send(fd, &priv, &pub);   break;
            case '2': do_tamper(fd, &priv, &pub);          break;
            case '3': do_manual_verify(&pub);              break;
            case '4': setup_keys(&priv, &pub);             break;
            case '5': do_show_keys(&priv, &pub);           break;
            case 'q': case 'Q':
                puts("\n  Closing connection. Goodbye!\n");
                close(fd);
                return EXIT_SUCCESS;
            default:
                print_warn("Unknown option. Enter 1–5 or q.");
        }
    }

    close(fd);
    return EXIT_SUCCESS;
}
