import numpy as np
import matplotlib.pyplot as plt

with open('../../sca/random_dataset/plaintexts.txt', 'r') as f:
    PLAINTEXTS = f.readlines()

with open('../../sca/random_dataset/keys.txt', 'r') as f:
    KEYS = f.readlines()

TRACES = 10_000
TIME_SAMPLES = 5_000

trace_matrix = np.zeros((TRACES, TIME_SAMPLES))
for i in range(TRACES):
    with open(f'../../sca/random_dataset/trace_{i}.txt', 'r') as f:
        trace_matrix[i] = [float(line) for line in f.readlines()]
        
SBOX = [
    0xC, 0x5, 0x6, 0xB,
    0x9, 0x0, 0xA, 0xD,
    0x3, 0xE, 0xF, 0x8,
    0x4, 0x7, 0x1, 0x2,
]

for nibble in range(16):
    NIBBLE = nibble

    signals = []
    for i in range(TRACES):
        p = int(PLAINTEXTS[i].strip()[-(NIBBLE + 1)], 16)
        k = int(KEYS[i].strip()[-(NIBBLE + 1)], 16)
        signals.append(SBOX[p ^ k])
    signals = np.array(signals)

    snr_values = np.zeros(TIME_SAMPLES)

    for t in range(TIME_SAMPLES):
        power_per_time_sample = trace_matrix[:, t]

        group_means = []
        group_variances = []

        for v in range(16): # For each S-box output 0-15
            # Find which traces resulted in this S-box value
            mask = (signals == v)
            group = power_per_time_sample[mask]

            if len(group) > 0:
                group_mean = sum(group) / len(group)
                group_means.append(group_mean)
                group_variance = sum((group_mean - el)**2 for el in group) / len(group)
                group_variances.append(group_variance)

        # SNR Formula: Var(Means) / Mean(Variances)
        groups_mean =  sum(group_means) / len(group_means)

        var_X = sum((groups_mean - el)**2 for el in group_means)
        var_N = sum(group_variances) / len(group_variances) / len(group_variances)

        snr_values[t] = var_X / var_N

    plt.plot(snr_values, color='blue', linewidth=1)

    plt.title(f'SNR Trace for Nibble {NIBBLE}', fontsize=14)
    plt.xlabel('Time Sample (t)', fontsize=12)
    plt.ylabel('SNR Value', fontsize=12)

    if NIBBLE == 8:
        poi = np.argsort(snr_values)[-3]
    else:
        poi = np.argmax(snr_values)
    plt.axvline(x=poi, color='red', linestyle='--', label=f'POI at {poi}')
    plt.legend()

    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(f'snr_plot_{NIBBLE}.png')
    print(f"Plot saved as snr_plot_{NIBBLE}.png. Peak found at sample {poi}.")

    print(f"The Point of Interest for Nibble {NIBBLE} is at sample {poi}")