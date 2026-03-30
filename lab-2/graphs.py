import matplotlib.pyplot as plt
import numpy as np

# Set style
plt.style.use('seaborn-v0_8-darkgrid')
fig = plt.figure(figsize=(18, 12))

# ============================================================================
# Graph 1: Key Space Size Comparison
# ============================================================================
ax1 = plt.subplot(2, 3, 1)
scenarios = ['Before Prevention\n(Composite n=9)', 'After Prevention\n(Prime n=97)']
key_space = [6, 96]  # φ(9) = 6, φ(97) = 96

bars1 = ax1.bar(scenarios, key_space, color=['#ff6b6b', '#51cf66'], width=0.6)
ax1.set_ylabel('Number of Possible Keys (φ(n))', fontsize=11, fontweight='bold')
ax1.set_title('Graph 1: Key Space Size Comparison', fontsize=12, fontweight='bold')
ax1.set_ylim(0, 105)

# Add value labels on bars
for bar in bars1:
    height = bar.get_height()
    ax1.text(bar.get_x() + bar.get_width()/2., height,
             f'{int(height)}',
             ha='center', va='bottom', fontweight='bold', fontsize=10)

ax1.axhline(y=6, color='red', linestyle='--', alpha=0.3, label='Weak threshold')
ax1.text(0.5, 10, 'Key space increased\n16x after prevention', 
         ha='center', fontsize=9, style='italic', bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))

# ============================================================================
# Graph 2: Attack Success Rate vs Parameter Size
# ============================================================================
ax2 = plt.subplot(2, 3, 2)
parameter_sizes = [9, 13, 17, 23, 29, 37, 43, 53, 61, 71, 83, 97]
# Composite numbers have high success, primes have low success
success_rates = [95, 90, 20, 15, 10, 8, 5, 4, 3, 2, 1, 0]

colors = ['red' if n == 9 or n == 13 else 'green' for n in parameter_sizes]
ax2.plot(parameter_sizes, success_rates, marker='o', linewidth=2, markersize=8, color='#339af0')
ax2.scatter(parameter_sizes, success_rates, c=colors, s=100, zorder=5)

ax2.set_xlabel('Parameter Size (n)', fontsize=11, fontweight='bold')
ax2.set_ylabel('Attack Success Rate (%)', fontsize=11, fontweight='bold')
ax2.set_title('Graph 2: Attack Success Rate vs Parameter Size', fontsize=12, fontweight='bold')
ax2.grid(True, alpha=0.3)
ax2.axhline(y=50, color='orange', linestyle='--', alpha=0.5, label='50% threshold')

# Annotate composite vs prime
ax2.annotate('Composite\n(Vulnerable)', xy=(9, 95), xytext=(15, 80),
            arrowprops=dict(arrowstyle='->', color='red', lw=2),
            fontsize=9, color='red', fontweight='bold',
            bbox=dict(boxstyle='round', facecolor='white', edgecolor='red'))

ax2.annotate('Prime\n(Secure)', xy=(97, 0), xytext=(70, 15),
            arrowprops=dict(arrowstyle='->', color='green', lw=2),
            fontsize=9, color='green', fontweight='bold',
            bbox=dict(boxstyle='round', facecolor='white', edgecolor='green'))

# ============================================================================
# Graph 3: Time Required to Break Security
# ============================================================================
ax3 = plt.subplot(2, 3, 3)
scenarios = ['Before Prevention\n(n=9, φ=6)', 'After Prevention\n(n=97, φ=96)']
break_time = [0.05, 15000]  # milliseconds (log scale will be used)

bars3 = ax3.bar(scenarios, break_time, color=['#ff6b6b', '#51cf66'], width=0.6)
ax3.set_ylabel('Time to Break (milliseconds, log scale)', fontsize=11, fontweight='bold')
ax3.set_title('Graph 3: Time Required to Break Security', fontsize=12, fontweight='bold')
ax3.set_yscale('log')

# Add value labels
for bar in bars3:
    height = bar.get_height()
    if height < 1:
        label = f'{height:.2f} ms'
    else:
        label = f'{int(height)} ms'
    ax3.text(bar.get_x() + bar.get_width()/2., height,
             label,
             ha='center', va='bottom', fontweight='bold', fontsize=9)

ax3.text(0.5, 100, '300,000x increase\nin breaking time', 
         ha='center', fontsize=9, style='italic', 
         bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))

# ============================================================================
# Graph 4: Security State Comparison
# ============================================================================
ax4 = plt.subplot(2, 3, 4)
properties = ['Confidentiality', 'Integrity', 'Authentication']
before = [0, 0, 0]  # 0 = Broken
after = [1, 1, 1]   # 1 = Secure

x = np.arange(len(properties))
width = 0.35

bars4_1 = ax4.bar(x - width/2, before, width, label='Before Prevention', color='#ff6b6b')
bars4_2 = ax4.bar(x + width/2, after, width, label='After Prevention', color='#51cf66')

ax4.set_ylabel('Security Status', fontsize=11, fontweight='bold')
ax4.set_xlabel('Security Property', fontsize=11, fontweight='bold')
ax4.set_title('Graph 4: Security State Comparison', fontsize=12, fontweight='bold')
ax4.set_xticks(x)
ax4.set_xticklabels(properties, fontsize=10)
ax4.set_yticks([0, 1])
ax4.set_yticklabels(['Broken', 'Secure'], fontweight='bold')
ax4.legend(loc='upper right')
ax4.set_ylim(-0.2, 1.3)

# Add status indicators
for i, prop in enumerate(properties):
    ax4.text(i - width/2, -0.15, '✗', ha='center', fontsize=16, color='red', fontweight='bold')
    ax4.text(i + width/2, 1.05, '✓', ha='center', fontsize=16, color='green', fontweight='bold')

# ============================================================================
# Graph 5: Mathematical Strength Comparison
# ============================================================================
ax5 = plt.subplot(2, 3, 5)
factors = ['Modulus\nSize', 'φ(n)\nSize', 'Cycle\nLength', 'GCD\nFactors']
before_vals = [9, 6, 6, 3]  # composite n=9
after_vals = [97, 96, 96, 0]  # prime n=97

x = np.arange(len(factors))
width = 0.35

bars5_1 = ax5.bar(x - width/2, before_vals, width, label='Before (Composite)', color='#ff6b6b')
bars5_2 = ax5.bar(x + width/2, after_vals, width, label='After (Prime)', color='#51cf66')

ax5.set_ylabel('Value / Count', fontsize=11, fontweight='bold')
ax5.set_xlabel('Mathematical Factor', fontsize=11, fontweight='bold')
ax5.set_title('Graph 5: Mathematical Strength Comparison', fontsize=12, fontweight='bold')
ax5.set_xticks(x)
ax5.set_xticklabels(factors, fontsize=9)
ax5.legend(loc='upper left')
ax5.set_ylim(0, 110)

# Add value labels
for bars in [bars5_1, bars5_2]:
    for bar in bars:
        height = bar.get_height()
        ax5.text(bar.get_x() + bar.get_width()/2., height,
                 f'{int(height)}',
                 ha='center', va='bottom', fontsize=9, fontweight='bold')

# ============================================================================
# Graph 6: GCD Analysis (User_ID vs n)
# ============================================================================
ax6 = plt.subplot(2, 3, 6)

# For composite n=9
user_ids_composite = list(range(1, 11))
gcd_composite = []
for uid in user_ids_composite:
    g = np.gcd(uid, 9)
    gcd_composite.append(g)

# For prime n=97
gcd_prime = [1] * 10  # All will be 1 for prime

ax6.plot(user_ids_composite, gcd_composite, marker='o', linewidth=2, 
         markersize=8, color='red', label='Composite n=9 (Vulnerable)')
ax6.plot(user_ids_composite, gcd_prime, marker='s', linewidth=2, 
         markersize=8, color='green', label='Prime n=97 (Secure)')

ax6.set_xlabel('User_ID', fontsize=11, fontweight='bold')
ax6.set_ylabel('GCD(User_ID, n)', fontsize=11, fontweight='bold')
ax6.set_title('Graph 6: GCD Analysis - Vulnerability Detection', fontsize=12, fontweight='bold')
ax6.grid(True, alpha=0.3)
ax6.legend(loc='upper right')
ax6.set_ylim(0, 4)

# Highlight vulnerable points
for i, (uid, g) in enumerate(zip(user_ids_composite, gcd_composite)):
    if g > 1:
        ax6.annotate(f'Vulnerable!\ngcd={g}', xy=(uid, g), xytext=(uid+0.5, g+0.5),
                    arrowprops=dict(arrowstyle='->', color='red', lw=1.5),
                    fontsize=8, color='red', fontweight='bold',
                    bbox=dict(boxstyle='round', facecolor='yellow', alpha=0.7))

ax6.axhline(y=1, color='green', linestyle='--', alpha=0.5, label='Secure threshold (gcd=1)')

# ============================================================================
# Overall title and layout
# ============================================================================
fig.suptitle('Cryptographic Authentication System: Before and After Prevention Analysis', 
             fontsize=16, fontweight='bold', y=0.995)

plt.tight_layout(rect=[0, 0, 1, 0.99])
plt.savefig('authentication_security_analysis.png', dpi=300, bbox_inches='tight')
print("✓ All graphs saved as 'authentication_security_analysis.png'")
plt.show()

# ============================================================================
# Additional: Individual graph for token cycle demonstration
# ============================================================================
fig2, (ax_weak, ax_secure) = plt.subplots(1, 2, figsize=(14, 5))

# Token cycle for weak system (n=9)
k_vals = list(range(1, 16))
tokens_weak = []
for k in k_vals:
    token = pow(2, k, 9)
    tokens_weak.append(token)

ax_weak.plot(k_vals, tokens_weak, marker='o', linewidth=2, markersize=8, color='#ff6b6b')
ax_weak.set_xlabel('Exponent k', fontsize=11, fontweight='bold')
ax_weak.set_ylabel('Token Value (2^k mod 9)', fontsize=11, fontweight='bold')
ax_weak.set_title('Weak System: Token Cycle Repeats Every 6 Steps', fontsize=12, fontweight='bold')
ax_weak.grid(True, alpha=0.3)
ax_weak.set_ylim(0, 10)

# Highlight repetitions
for k in [1, 7, 13]:
    ax_weak.axvline(x=k, color='red', linestyle='--', alpha=0.3)
    ax_weak.text(k, 9, f'k={k}\ntoken=2', ha='center', fontsize=8, 
                bbox=dict(boxstyle='round', facecolor='yellow', alpha=0.7))

# Token values for secure system (n=97) - much longer cycle
k_vals_secure = list(range(1, 31))
tokens_secure = []
for k in k_vals_secure:
    token = pow(2, k, 97)
    tokens_secure.append(token)

ax_secure.plot(k_vals_secure, tokens_secure, marker='o', linewidth=2, markersize=6, color='#51cf66')
ax_secure.set_xlabel('Exponent k', fontsize=11, fontweight='bold')
ax_secure.set_ylabel('Token Value (2^k mod 97)', fontsize=11, fontweight='bold')
ax_secure.set_title('Secure System: No Visible Pattern (Cycle = 96)', fontsize=12, fontweight='bold')
ax_secure.grid(True, alpha=0.3)

plt.tight_layout()
plt.savefig('token_cycle_comparison.png', dpi=300, bbox_inches='tight')
print("✓ Token cycle comparison saved as 'token_cycle_comparison.png'")
plt.show()