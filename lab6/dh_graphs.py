#!/usr/bin/env python3
"""
================================================================
  Diffie-Hellman Key Exchange — Visualization Suite
  Generates 6 publication-quality graphs:
    1. Protocol flow diagram (step-by-step)
    2. Modular exponentiation timing vs exponent bit-length
    3. Key-space distribution (public keys mod p)
    4. Avalanche effect: bit flips in private key → output change
    5. Timing breakdown bar chart (from dh_stats.csv if present)
    6. Discrete logarithm hardness (brute-force search steps)
================================================================
"""

import os
import sys
import math
import time
import random
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.gridspec as gridspec
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch
from collections import defaultdict

# ──────────────────────────────────────────────────────────────
#  DH parameters (must match C code)
# ──────────────────────────────────────────────────────────────
P = 2**61 - 1          # Mersenne prime
G = 2
STYLE = "dark_background"

plt.style.use(STYLE)
PALETTE = {
    "alice":  "#00d4ff",
    "bob":    "#ff6b6b",
    "shared": "#51cf66",
    "accent": "#ffd43b",
    "dim":    "#555555",
    "bg":     "#1a1a2e",
    "grid":   "#2a2a4a",
}

# ──────────────────────────────────────────────────────────────
#  Helpers
# ──────────────────────────────────────────────────────────────
def mod_pow_py(base, exp, mod):
    return pow(base, exp, mod)

def time_mod_pow(bits):
    """Return average ns for mod_pow with `bits`-bit exponent."""
    exp = random.getrandbits(bits)
    base = random.randint(2, P - 1)
    N = max(1, 200 // bits)
    t0 = time.perf_counter_ns()
    for _ in range(N):
        pow(base, exp, P)
    return (time.perf_counter_ns() - t0) / N

# ──────────────────────────────────────────────────────────────
#  FIGURE 1 — Protocol Flow Diagram
# ──────────────────────────────────────────────────────────────
def fig_protocol_flow(ax):
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 14)
    ax.axis("off")
    ax.set_facecolor(PALETTE["bg"])
    ax.set_title("Diffie-Hellman Protocol Flow", color="white",
                 fontsize=14, fontweight="bold", pad=10)

    # Column headers
    for x, label, color in [(2, "ALICE (Server)", PALETTE["alice"]),
                             (8, "BOB (Client)",   PALETTE["bob"])]:
        ax.text(x, 13.5, label, ha="center", va="center", fontsize=11,
                fontweight="bold", color=color,
                bbox=dict(boxstyle="round,pad=0.4", fc=color+"22", ec=color, lw=1.5))

    # Vertical timelines
    for x, c in [(2, PALETTE["alice"]), (8, PALETTE["bob"])]:
        ax.plot([x, x], [0.5, 13], color=c, lw=1.5, alpha=0.4, ls="--")

    steps = [
        # (y,   side,   text,              arrow_dir)
        (12.5,  "both",  "Agree on public params:\np = 2^61-1,  g = 2",  None),
        (11.0,  "left",  "Choose private\nx_a = random",                  None),
        (11.0,  "right", "Choose private\nx_b = random",                  None),
        (9.5,   "left",  "Compute\nA = g^x_a mod p",                      None),
        (9.5,   "right", "Compute\nB = g^x_b mod p",                      None),
        (8.0,   "arrow", "A  ──────────────────→",                        "lr"),
        (7.0,   "arrow", "B  ←──────────────────",                        "rl"),
        (5.8,   "left",  "Compute\nS = B^x_a mod p",                      None),
        (5.8,   "right", "Compute\nS = A^x_b mod p",                      None),
        (4.5,   "both",  "Both get same S  ✓\n(Discrete log prevents attacker finding S)", None),
        (3.0,   "both",  "Derive session key K = KDF(S)\nEncrypt messages with K",  None),
    ]

    for y, side, text, _ in steps:
        if side == "left":
            ax.text(2, y, text, ha="center", va="center", fontsize=8,
                    color=PALETTE["alice"],
                    bbox=dict(boxstyle="round,pad=0.3", fc=PALETTE["alice"]+"15",
                              ec=PALETTE["alice"]+"50", lw=1))
        elif side == "right":
            ax.text(8, y, text, ha="center", va="center", fontsize=8,
                    color=PALETTE["bob"],
                    bbox=dict(boxstyle="round,pad=0.3", fc=PALETTE["bob"]+"15",
                              ec=PALETTE["bob"]+"50", lw=1))
        elif side == "both":
            ax.text(5, y, text, ha="center", va="center", fontsize=8.5,
                    color=PALETTE["accent"],
                    bbox=dict(boxstyle="round,pad=0.4", fc=PALETTE["accent"]+"15",
                              ec=PALETTE["accent"]+"60", lw=1.2))
        elif side == "arrow":
            if _ == "lr":
                ax.annotate("", xy=(7.5, y), xytext=(2.5, y),
                            arrowprops=dict(arrowstyle="->", color=PALETTE["shared"],
                                           lw=2, connectionstyle="arc3,rad=0"))
                ax.text(5, y + 0.3, "A (public)", ha="center", fontsize=7.5,
                        color=PALETTE["shared"])
            else:
                ax.annotate("", xy=(2.5, y), xytext=(7.5, y),
                            arrowprops=dict(arrowstyle="->", color=PALETTE["shared"],
                                           lw=2, connectionstyle="arc3,rad=0"))
                ax.text(5, y + 0.3, "B (public)", ha="center", fontsize=7.5,
                        color=PALETTE["shared"])

# ──────────────────────────────────────────────────────────────
#  FIGURE 2 — Modular Exponentiation Timing
# ──────────────────────────────────────────────────────────────
def fig_modexp_timing(ax):
    ax.set_facecolor(PALETTE["bg"])
    bit_lengths = [4, 8, 12, 16, 24, 32, 48, 61]
    times_ns = [time_mod_pow(b) for b in bit_lengths]

    ax.plot(bit_lengths, times_ns, "o-", color=PALETTE["alice"],
            lw=2, ms=7, label="Measured time")

    # Theoretical O(log n) reference
    ref = times_ns[0] * np.array(bit_lengths) / bit_lengths[0]
    ax.plot(bit_lengths, ref, "--", color=PALETTE["dim"], lw=1.5,
            label="O(bits) reference")

    ax.set_xlabel("Exponent bit-length", color="white")
    ax.set_ylabel("Time (ns)", color="white")
    ax.set_title("Modular Exponentiation Timing\n(Binary exponentiation, mod 2^61-1)",
                 color="white", fontsize=11)
    ax.legend(facecolor="#222", edgecolor="#555", labelcolor="white")
    ax.grid(color=PALETTE["grid"], ls="--", lw=0.6)
    ax.tick_params(colors="white")
    for spine in ax.spines.values():
        spine.set_edgecolor("#444")

# ──────────────────────────────────────────────────────────────
#  FIGURE 3 — Public Key Distribution
# ──────────────────────────────────────────────────────────────
def fig_key_distribution(ax):
    ax.set_facecolor(PALETTE["bg"])
    N = 4000
    privs = [random.randint(2, P - 2) for _ in range(N)]
    pubs  = [pow(G, x, P) for x in privs]

    # Normalize to [0,1] for display
    norm_pubs = [x / P for x in pubs]

    # Histogram
    counts, bins, patches = ax.hist(norm_pubs, bins=50,
                                    color=PALETTE["bob"], alpha=0.75, edgecolor="#111")

    # Uniform reference line
    expected = N / 50
    ax.axhline(expected, color=PALETTE["accent"], lw=1.5, ls="--",
               label=f"Uniform expected ({expected:.0f})")

    ax.set_xlabel("Public key value (normalised, 0–1)", color="white")
    ax.set_ylabel("Count", color="white")
    ax.set_title(f"Public Key Distribution  (N={N} samples)\ng^x mod p appears uniform ← discrete log hardness",
                 color="white", fontsize=11)
    ax.legend(facecolor="#222", edgecolor="#555", labelcolor="white")
    ax.grid(color=PALETTE["grid"], ls="--", lw=0.6, axis="y")
    ax.tick_params(colors="white")
    for spine in ax.spines.values():
        spine.set_edgecolor("#444")

# ──────────────────────────────────────────────────────────────
#  FIGURE 4 — Avalanche Effect
# ──────────────────────────────────────────────────────────────
def fig_avalanche(ax):
    ax.set_facecolor(PALETTE["bg"])
    base_priv = random.randint(2, P - 2)
    base_pub  = pow(G, base_priv, P)

    bit_flips = list(range(1, 62))
    hamming_diffs = []
    for flip in bit_flips:
        flipped_priv = base_priv ^ (1 << (flip - 1)) & (P - 1)
        if flipped_priv < 2 or flipped_priv >= P - 1:
            flipped_priv = base_priv ^ (1 << (flip - 1) % 30)
        flipped_pub = pow(G, flipped_priv, P)
        diff = bin(base_pub ^ flipped_pub).count("1")
        hamming_diffs.append(diff)

    ax.bar(bit_flips, hamming_diffs, color=PALETTE["shared"],
           alpha=0.8, edgecolor="#111", width=0.8)
    ax.axhline(30.5, color=PALETTE["accent"], lw=1.5, ls="--",
               label="50% (ideal avalanche)")

    ax.set_xlabel("Bit position flipped in private key", color="white")
    ax.set_ylabel("Bits changed in public key (Hamming dist)", color="white")
    ax.set_title("Avalanche Effect\n(1-bit change in x → ~50% bits change in g^x mod p)",
                 color="white", fontsize=11)
    ax.set_ylim(0, 65)
    ax.legend(facecolor="#222", edgecolor="#555", labelcolor="white")
    ax.grid(color=PALETTE["grid"], ls="--", lw=0.6, axis="y")
    ax.tick_params(colors="white")
    for spine in ax.spines.values():
        spine.set_edgecolor("#444")

# ──────────────────────────────────────────────────────────────
#  FIGURE 5 — Timing Breakdown (from CSV or synthetic)
# ──────────────────────────────────────────────────────────────
def fig_timing_breakdown(ax):
    ax.set_facecolor(PALETTE["bg"])

    # Try to load real CSV data
    roles, key_gen, mod_exp, kdf, enc, dec = [], [], [], [], [], []
    try:
        import csv
        with open("dh_stats.csv") as f:
            reader = csv.DictReader(f)
            for row in reader:
                roles.append(row["role"])
                key_gen.append(float(row["key_gen_ns"]) / 1000)
                mod_exp.append(float(row["mod_exp_ns"]) / 1000)
                kdf.append(float(row["kdf_ns"]) / 1000)
                enc.append(float(row["encrypt_ns"]) / 1000)
                dec.append(float(row["decrypt_ns"]) / 1000)
        title_suffix = "(from dh_stats.csv)"
    except Exception:
        # Synthetic data
        for r in ["Server", "Client"]:
            roles.append(r)
            key_gen.append(random.uniform(1, 4))
            mod_exp.append(random.uniform(15, 40))
            kdf.append(random.uniform(8, 20))
            enc.append(random.uniform(0.5, 2))
            dec.append(random.uniform(0.5, 2))
        title_suffix = "(synthetic — run C code to get real data)"

    x = np.arange(len(roles))
    w = 0.15
    cols = [PALETTE["alice"], PALETTE["bob"], PALETTE["shared"],
            PALETTE["accent"], "#ff9ff3"]
    labels = ["Key Gen", "Mod Exp", "KDF", "Encrypt", "Decrypt"]
    data   = [key_gen, mod_exp, kdf, enc, dec]

    for i, (d, l, c) in enumerate(zip(data, labels, cols)):
        ax.bar(x + i * w, d, w, label=l, color=c, alpha=0.85, edgecolor="#111")

    ax.set_xticks(x + w * 2)
    ax.set_xticklabels(roles, color="white")
    ax.set_ylabel("Time (µs)", color="white")
    ax.set_title(f"Per-Phase Timing Breakdown\n{title_suffix}",
                 color="white", fontsize=11)
    ax.legend(facecolor="#222", edgecolor="#555", labelcolor="white",
              ncol=3, fontsize=8)
    ax.grid(color=PALETTE["grid"], ls="--", lw=0.6, axis="y")
    ax.tick_params(colors="white")
    for spine in ax.spines.values():
        spine.set_edgecolor("#444")

# ──────────────────────────────────────────────────────────────
#  FIGURE 6 — Discrete Log Hardness (brute force steps)
# ──────────────────────────────────────────────────────────────
def fig_dlog_hardness(ax):
    ax.set_facecolor(PALETTE["bg"])
    key_bits = np.arange(8, 200, 4)

    # Brute-force: 2^n steps
    brute = 2.0 ** key_bits / 1e9  # seconds at 10^9 ops/sec

    # Baby-step giant-step: 2^(n/2) steps
    bsgs = 2.0 ** (key_bits / 2) / 1e9

    # Index calculus (approx): exp(1.923 * n^(1/3) * (ln n)^(2/3))
    # Simplified NFS approximation
    n = key_bits
    nfs = np.exp(1.923 * (n ** (1/3)) * (np.log(n) ** (2/3))) / 1e9

    ax.semilogy(key_bits, brute, color=PALETTE["alice"],  lw=2, label="Brute force O(2^n)")
    ax.semilogy(key_bits, bsgs,  color=PALETTE["bob"],   lw=2, label="BSGS O(2^(n/2))")
    ax.semilogy(key_bits, nfs,   color=PALETTE["shared"], lw=2, label="Index Calculus / NFS")

    # Reference lines
    for y, label, col in [
        (1,         "1 second",    "#888"),
        (3.15e7,    "1 year",      PALETTE["accent"]),
        (3.15e17,   "Age of universe", "#ff9ff3"),
    ]:
        ax.axhline(y, ls=":", lw=1, color=col, alpha=0.7)
        ax.text(key_bits[-1] * 0.98, y * 1.5, label, ha="right",
                fontsize=7, color=col, alpha=0.9)

    ax.axvline(61, ls="--", lw=1.5, color=PALETTE["accent"], alpha=0.8,
               label="Our key size (61 bits)")

    ax.set_xlabel("Key size (bits)", color="white")
    ax.set_ylabel("Time to break (seconds, log scale)", color="white")
    ax.set_title("Discrete Logarithm Hardness\n(Why larger keys matter)",
                 color="white", fontsize=11)
    ax.legend(facecolor="#222", edgecolor="#555", labelcolor="white", fontsize=8)
    ax.grid(color=PALETTE["grid"], ls="--", lw=0.5)
    ax.tick_params(colors="white")
    for spine in ax.spines.values():
        spine.set_edgecolor("#444")

# ──────────────────────────────────────────────────────────────
#  Compose all figures
# ──────────────────────────────────────────────────────────────
def main():
    print("Generating DH visualization suite...")
    fig = plt.figure(figsize=(20, 24), facecolor=PALETTE["bg"])
    fig.suptitle(
        "Diffie-Hellman Key Exchange — Complete Analysis Suite\n"
        "Safe prime p = 2^61-1  |  Generator g = 2  |  64-bit keys",
        fontsize=16, fontweight="bold", color="white", y=0.98
    )

    gs = gridspec.GridSpec(3, 2, figure=fig, hspace=0.45, wspace=0.35,
                           top=0.94, bottom=0.04, left=0.07, right=0.97)

    axes = [
        fig.add_subplot(gs[0, 0]),
        fig.add_subplot(gs[0, 1]),
        fig.add_subplot(gs[1, 0]),
        fig.add_subplot(gs[1, 1]),
        fig.add_subplot(gs[2, 0]),
        fig.add_subplot(gs[2, 1]),
    ]

    funcs = [
        fig_protocol_flow,
        fig_modexp_timing,
        fig_key_distribution,
        fig_avalanche,
        fig_timing_breakdown,
        fig_dlog_hardness,
    ]
    labels = [
        "(1) Protocol Flow",
        "(2) Mod-Exp Timing",
        "(3) Key Distribution",
        "(4) Avalanche Effect",
        "(5) Phase Timing",
        "(6) DLog Hardness",
    ]

    for ax, fn, lbl in zip(axes, funcs, labels):
        print(f"  Drawing {lbl}...")
        fn(ax)

    out = "dh_visualization.png"
    fig.savefig(out, dpi=150, bbox_inches="tight", facecolor=PALETTE["bg"])
    print(f"\n✔ Saved → {out}")
    print("  Run the C server/client first to populate dh_stats.csv for real timing data.")

if __name__ == "__main__":
    main()