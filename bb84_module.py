import numpy as np
import hashlib

def run_bb84(n_qubits=512, error_threshold=0.11, eve=False):
    """
    Simulates BB84 Quantum Key Distribution protocol.
    Returns: dict with final key bits (str) and acceptance status.
    """

    # Random bits and bases
    alice_bits = np.random.randint(0, 2, n_qubits)
    alice_bases = np.random.randint(0, 2, n_qubits)
    bob_bases = np.random.randint(0, 2, n_qubits)

    # Simulate Eve intercept-resend attack (optional)
    if eve:
        eve_bases = np.random.randint(0, 2, n_qubits)
        intercepted = []
        for i in range(n_qubits):
            intercepted.append(alice_bits[i] if alice_bases[i] == eve_bases[i] else np.random.randint(0, 2))
        transmitted = intercepted
    else:
        transmitted = alice_bits

    # Bob measures
    bob_results = []
    for i in range(n_qubits):
        if bob_bases[i] == (alice_bases[i] if not eve else np.random.randint(0, 2)):
            bob_results.append(transmitted[i])
        else:
            bob_results.append(np.random.randint(0, 2))
    bob_results = np.array(bob_results)

    # Sifting — keep bits where bases match
    mask = alice_bases == bob_bases
    sifted_alice = alice_bits[mask]
    sifted_bob = bob_results[mask]
    key_length = len(sifted_alice)

    # QBER estimation (use random sample)
    sample_size = min(100, key_length // 2)
    sample_idx = np.random.choice(key_length, sample_size, replace=False)
    qber = np.mean(sifted_alice[sample_idx] != sifted_bob[sample_idx])

    # Abort if too noisy
    accepted = qber <= error_threshold
    if not accepted:
        print(f"❌ QBER too high ({qber:.2f}) — possible eavesdropper!")
        return {"accepted": False, "final_key": None}

    # Privacy amplification (hash)
    sifted_str = ''.join(map(str, sifted_alice))
    hashed_bits = hashlib.sha256(sifted_str.encode()).hexdigest()
    final_key_bits = bin(int(hashed_bits, 16))[2:].zfill(256)[:128]  # 128 bits

    return {
        "accepted": True,
        "final_key": final_key_bits,
        "qber": qber,
        "length": key_length
    }

if __name__ == "__main__":
    result = run_bb84(n_qubits=512)
    print("BB84 Result:", result)
