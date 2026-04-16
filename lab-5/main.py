import math

import numpy as np
import matplotlib.pyplot as plt

# ------- READ DATA

TARGET_NIBBLE = 15

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

with open('../../sca/random_pt_dataset/plaintexts.txt', 'r') as f:
    ATTACK_PLAINTEXTS = f.readlines()
    
ATTACK_TRACES = 5_000
ATTACK_TIME_SAMPLES = 5_000

attack_trace_matrix = np.zeros((ATTACK_TRACES, ATTACK_TIME_SAMPLES))
for i in range(ATTACK_TRACES):
    with open(f'../../sca/random_pt_dataset/trace_{i}.txt', 'r') as f:
        attack_trace_matrix[i] = [float(line) for line in f.readlines()]

# -------

SBOX = [
    0xC, 0x5, 0x6, 0xB,
    0x9, 0x0, 0xA, 0xD,
    0x3, 0xE, 0xF, 0x8,
    0x4, 0x7, 0x1, 0x2,
]

attack_plaintext_nibbles = []
for i in range(ATTACK_TRACES):
    attack_plaintext_nibbles.append(int(ATTACK_PLAINTEXTS[i].strip()[-(TARGET_NIBBLE + 1)], 16))
    
plaintext_nibbles = []
for i in range(TRACES):
    plaintext_nibbles.append(int(PLAINTEXTS[i].strip()[-(TARGET_NIBBLE + 1)], 16))

key_nibbles = []
for i in range(TRACES):
    key_nibbles.append(int(KEYS[i].strip()[-(TARGET_NIBBLE + 1)], 16))
    
signals = []
for i in range(TRACES):
    signals = SBOX[key_nibbles[i] ^ plaintext_nibbles[i]]

POI_identity = 572

v_hypothethical = np.zeros((16, ATTACK_TRACES))
for i in range(16):
    k_i = i
    for j in range(ATTACK_TRACES):
        p_j = attack_plaintext_nibbles[j]
        v_hypothethical[i][j] = SBOX[p_j ^ k_i]

# ------- BUILD TEMPLATES
poi_leakage = [[] for _ in range(16)] 
for j in range(TRACES):
    p = plaintext_nibbles[j]
    k = key_nibbles[j]
    v = SBOX[k^p]
    poi_leakage[v].append(trace_matrix[j, POI_identity])

mean_vector = [0 for __ in range(16)]
for i in range(16):
    mean_vector[i] = np.mean(poi_leakage[i])
    
cov_matrix = [[] for _ in range(16)]
for i in range(16):
    cov_matrix[i] = np.cov(poi_leakage[i], bias=True)

# print(mean_vector, cov_matrix)
# print(mean_vector[0xC], cov_matrix[0xC])

# ------ STATISTICAL ANALYSIS
def template_prob_score(traces_no):
    prob = [0 for _ in range(16)]#score for each key hypothesis
    
    #group the traces according to the key hypothesis
    for k in range(16): #for each key hypothesis
        #compute score of each trace
        for j in range(traces_no): #for each trace
            p = attack_plaintext_nibbles[j]
            v = SBOX[k ^ p] #compute the intermediate value

            #leakges at POIs
            trace_leakage = attack_trace_matrix[j, POI_identity]
            #compute the score of this trace using the template
            mean_dif = trace_leakage-mean_vector[v]
                        
            trace_prob = math.log(cov_matrix[v]) + (mean_dif * mean_dif) / cov_matrix[v]
            prob[k] -= trace_prob
    
    return prob

def compute_rank(probs, key):
    prob_sorted = []
    for k in range(16):
        prob_sorted.append(probs[k])
    prob_correct = prob_sorted[key]
    prob_sorted.sort()
    rank = prob_sorted.index(prob_correct)
    return 16-rank #the key with the lowest score is the best

def prob_score(max_no_trace):
    #probability score for all key hypotheses
    max_ = 0
    max_ind = 0
    
    all_prob_score = [[0 for __ in range(max_no_trace)] for _ in range(16)]
    for no_of_traces in range(1, max_no_trace):
        probs = template_prob_score(no_of_traces)
        for k in range(16):
            all_prob_score[k][no_of_traces] = probs[k]
            if probs[k] > max_:
                max_ind = k
                max_ = probs[k]
    
    #plot probability scores
    x = []
    for no_of_traces in range(max_no_trace):
        x.append(no_of_traces)
    for k in range(16):
        if k == max_ind:
            plt.plot(x,all_prob_score[k],'b')
        else:
            plt.plot(x,all_prob_score[k],color="#808080")
    
    plt.title('Probability scores')
    plt.show()
    
    return all_prob_score, max_ind

print(prob_score(50)[1])
