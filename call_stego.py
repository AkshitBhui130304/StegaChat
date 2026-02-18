"""
In-memory steganography for real-time video call.
Uses BB84-derived key for AES encryption and position randomization.
Supports: audio chunks (raw PCM), video frames (BGR numpy), image (RGB numpy).
"""

import struct
import zlib
import hashlib
import random
import numpy as np
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# --- Key derivation from BB84 bit string (128 bits) ---
def bb84_key_to_aes_key(bb84_bits: str) -> bytes:
    """Convert BB84 final_key (binary string) to 32-byte AES key."""
    return hashlib.sha256(bb84_bits.encode() if isinstance(bb84_bits, str) else bb84_bits).digest()


def encrypt_with_key(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt with AES-256 EAX. Returns: nonce + tag + ciphertext (key is 32 bytes)."""
    cipher = AES.new(key, AES.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce + tag + ct


def decrypt_with_key(blob: bytes, key: bytes) -> bytes:
    """Decrypt blob from encrypt_with_key."""
    nonce, tag = blob[:16], blob[16:32]
    ct = blob[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)


def _shuffled_indices(n: int, seed_bytes: bytes) -> list:
    """Deterministic shuffle of range(n) using seed for reproducibility."""
    seed = int.from_bytes(hashlib.sha256(seed_bytes).digest()[:8], 'big')
    rng = random.Random(seed)
    idx = list(range(n))
    rng.shuffle(idx)
    return idx


def _bytes_to_bits(b: bytes) -> str:
    return ''.join(f"{x:08b}" for x in b)


def _bits_to_bytes(s: str) -> bytes:
    s = s[:len(s) - (len(s) % 8)]
    return bytes(int(s[i:i+8], 2) for i in range(0, len(s), 8))


# --- Audio: simple LSB, all samples eligible, no amplitude gating ---
# No sample-level threshold; capacity_bits = total_samples_in_chunk (1 bit per sample).


def _audio_embedding_positions(samples: np.ndarray, sample_rate: int = 48000) -> np.ndarray:
    """
    All samples are eligible for LSB embedding. No amplitude/RMS gating.
    capacity_bits = len(samples); 1 sample = 1 bit.
    """
    return np.arange(len(samples))


def payload_to_bitstream(payload: bytes, key: bytes) -> str:
    """Build the full bitstream (32-bit length header + encrypted payload) for streaming embed."""
    encrypted = encrypt_with_key(zlib.compress(payload, level=9), key)
    header = struct.pack(">I", len(encrypted) * 8)
    return _bytes_to_bits(header + encrypted)


def embed_in_audio_chunk(samples: np.ndarray, payload: bytes, key: bytes, sample_rate: int = 48000):
    """
    Embed payload into LSB of eligible samples. Never throws.
    Returns (stego_samples, bits_remaining). If bits_remaining > 0, caller should send more audio.
    Uses 1 LSB per sample; max change per sample is 1.
    """
    bitstream = payload_to_bitstream(payload, key)
    stego, n_embed, remainder = embed_bits_into_audio(samples, bitstream, sample_rate)
    bits_remaining = len(remainder)
    return stego, bits_remaining


def embed_bits_into_audio(samples: np.ndarray, bitstream: str, sample_rate: int = 48000):
    """
    Embed a bit string into samples (LSB only). Used for streaming continuation.
    Returns (stego_samples, bits_embedded, bits_remaining).
    bitstream is consumed from the start; remaining = bitstream[bits_embedded:].
    """
    positions = _audio_embedding_positions(samples, sample_rate)
    capacity_bits = len(positions)
    n_embed = min(len(bitstream), capacity_bits)
    out = samples.copy()
    for k in range(n_embed):
        idx = int(positions[k])
        b = int(bitstream[k])
        val = (int(out[idx]) & 0xFFFE) | b
        val = val & 0xFFFF
        if val >= 32768:
            val = val - 65536
        out[idx] = np.int16(val)
    return out, n_embed, bitstream[n_embed:]


def extract_from_audio_chunk(samples: np.ndarray, key: bytes, sample_rate: int = 48000) -> bytes:
    """Extract and decrypt payload from LSB; same positions as embed (all samples, 1 bit per sample)."""
    positions = _audio_embedding_positions(samples, sample_rate)
    if len(positions) < 32:
        raise ValueError("Chunk too small for header.")
    header_bits = "".join(str(int(samples[int(positions[i])]) & 1) for i in range(32))
    payload_bits_len = struct.unpack(">I", _bits_to_bytes(header_bits))[0]
    total_bits = 32 + payload_bits_len
    if len(positions) < total_bits:
        raise ValueError("No hidden message in this audio or chunk truncated.")
    payload_bits = "".join(str(int(samples[int(positions[i])]) & 1) for i in range(32, total_bits))
    blob = _bits_to_bytes(payload_bits)
    return zlib.decompress(decrypt_with_key(blob, key))


# --- Video frame / Image: BGR or RGB numpy, LSB per channel ---
def embed_in_frame(frame: np.ndarray, payload: bytes, key: bytes) -> np.ndarray:
    """
    frame: HxWxC uint8. Embeds encrypted payload in LSB; uses 32-bit length header.
    Optionally randomize positions using key. Returns new frame.
    """
    encrypted = encrypt_with_key(zlib.compress(payload, level=9), key)
    header = struct.pack(">I", len(encrypted) * 8)
    full = header + encrypted
    bits = _bytes_to_bits(full)
    flat = frame.flatten()
    if len(bits) > len(flat):
        raise ValueError("Payload too large for this frame.")
    indices = _shuffled_indices(len(flat), key)[:len(bits)]
    # sort so we write in deterministic order (by index)
    order = sorted(range(len(bits)), key=lambda i: indices[i])
    out = flat.copy()
    for pos, bit in enumerate(bits):
        idx = indices[pos]
        out[idx] = (int(out[idx]) & 0xFE) | int(bit)
    return out.reshape(frame.shape).astype(np.uint8)


def extract_from_frame(frame: np.ndarray, key: bytes) -> bytes:
    """Extract payload from frame LSBs (read in same order as embed: indices[0], indices[1], ...)."""
    flat = frame.flatten()
    if flat.size < 32:
        raise ValueError("Frame too small.")
    indices = _shuffled_indices(len(flat), key)
    # Read bits in same order as written: flat[indices[0]], flat[indices[1]], ...
    header_bits = ''.join(str(int(flat[indices[i]]) & 1) for i in range(32))
    payload_bits_len = struct.unpack(">I", _bits_to_bytes(header_bits))[0]
    total_bits = 32 + payload_bits_len
    if flat.size < total_bits:
        raise ValueError("Frame truncated.")
    payload_bits = ''.join(str(int(flat[indices[i]]) & 1) for i in range(32, total_bits))
    blob = _bits_to_bytes(payload_bits)
    return zlib.decompress(decrypt_with_key(blob, key))


# --- Video: multi-frame embed / extract (recorded video as cover) ---
def embed_in_frames(frames: list, payload: bytes, key: bytes) -> list:
    """
    Embed payload across multiple frames (video steganography).
    First frame stores 32-bit total payload length (in bits), then payload bits
    are distributed across all frames. Returns list of stego frames (new arrays).
    """
    if not frames:
        raise ValueError("No frames.")
    encrypted = encrypt_with_key(zlib.compress(payload, level=9), key)
    total_payload_bits = len(encrypted) * 8
    full_bits = _bytes_to_bits(struct.pack(">I", total_payload_bits) + encrypted)
    capacities = []
    for i, f in enumerate(frames):
        cap = frame_capacity_bits(f)
        if i == 0:
            cap -= 32
        capacities.append(max(0, cap))
    total_cap = 32 + sum(capacities)
    if len(full_bits) > total_cap:
        raise ValueError("Payload too large for this video (need more or larger frames).")
    out_frames = []
    bit_offset = 0
    for i, f in enumerate(frames):
        flat = f.flatten()
        indices = _shuffled_indices(len(flat), key + struct.pack(">I", i))[: len(flat)]
        order = sorted(range(len(flat)), key=lambda j: indices[j])
        n_bits = (32 + capacities[0]) if i == 0 else capacities[i]
        n_bits = min(n_bits, len(full_bits) - bit_offset)
        out = flat.copy()
        for j in range(n_bits):
            b = int(full_bits[bit_offset + j])
            idx = order[j]
            out[idx] = (int(out[idx]) & 0xFE) | b
        bit_offset += n_bits
        out_frames.append(out.reshape(f.shape).astype(np.uint8))
    return out_frames


def extract_from_frames(frames: list, key: bytes) -> bytes:
    """Extract payload from multiple frames (inverse of embed_in_frames)."""
    if not frames:
        raise ValueError("No frames.")
    capacities = []
    for i, f in enumerate(frames):
        cap = frame_capacity_bits(f)
        if i == 0:
            cap -= 32
        capacities.append(max(0, cap))
    bits_list = []
    bit_offset = 0
    for i, f in enumerate(frames):
        flat = f.flatten()
        indices = _shuffled_indices(len(flat), key + struct.pack(">I", i))[: len(flat)]
        order = sorted(range(len(flat)), key=lambda j: indices[j])
        n_bits = (32 + capacities[0]) if i == 0 else capacities[i]
        for j in range(n_bits):
            idx = order[j]
            bits_list.append(str(int(flat[idx]) & 1))
        bit_offset += n_bits
    all_bits = "".join(bits_list)
    if len(all_bits) < 32:
        raise ValueError("Video truncated.")
    header_bits = all_bits[:32]
    payload_bits_len = struct.unpack(">I", _bits_to_bytes(header_bits))[0]
    total_payload_bits = 32 + payload_bits_len
    if len(all_bits) < total_payload_bits:
        raise ValueError("Video truncated.")
    payload_bits = all_bits[32:total_payload_bits]
    blob = _bits_to_bytes(payload_bits)
    return zlib.decompress(decrypt_with_key(blob, key))


# --- Helpers for capacity (encrypted payload bytes that fit) ---
def audio_capacity_bytes(samples: np.ndarray, sample_rate: int = 48000) -> int:
    """Max encrypted payload bytes that fit (sparse LSB: eligible positions minus 32-bit header)."""
    positions = _audio_embedding_positions(samples, sample_rate)
    return max(0, (len(positions) - 32) // 8)


def frame_capacity_bits(frame: np.ndarray) -> int:
    """Max payload bits (minus 32-bit header)."""
    return max(0, frame.size - 32)


def video_capacity_bits(frames: list) -> int:
    """Total payload bits that fit across frames (first frame loses 32 for header)."""
    if not frames:
        return 0
    total = frame_capacity_bits(frames[0]) - 32
    for f in frames[1:]:
        total += frame_capacity_bits(f)
    return max(0, total)
