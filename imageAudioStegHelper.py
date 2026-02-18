# ============================================================
# imageAudioStegHelper_autoResize.py
# ============================================================

import os
import io
import math
import wave
import numpy as np
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import struct
import pickle

# ---------------- Huffman Compression ----------------
from collections import Counter
import heapq

class HuffmanNode:
    def __init__(self, byte=None, freq=0, left=None, right=None):
        self.byte = byte
        self.freq = freq
        self.left = left
        self.right = right
    def __lt__(self, other):
        return self.freq < other.freq

def huffman_compress(data: bytes) -> bytes:
    freq = Counter(data)
    heap = [HuffmanNode(b, f) for b, f in freq.items()]
    heapq.heapify(heap)

    while len(heap) > 1:
        l, r = heapq.heappop(heap), heapq.heappop(heap)
        node = HuffmanNode(None, l.freq + r.freq, l, r)
        heapq.heappush(heap, node)

    codes = {}
    def assign(node, code):
        if node.byte is not None:
            codes[node.byte] = code
        else:
            assign(node.left, code + "0")
            assign(node.right, code + "1")
    assign(heap[0], "")

    encoded = "".join(codes[b] for b in data)
    padding = 8 - len(encoded) % 8
    encoded += "0" * padding
    out = bytes([padding]) + bytes(int(encoded[i:i+8], 2) for i in range(0, len(encoded), 8))
    return pickle.dumps((freq, out))

def huffman_decompress(packed: bytes) -> bytes:
    freq, out = pickle.loads(packed)
    padding = out[0]
    bitstring = "".join(f"{byte:08b}" for byte in out[1:])
    bitstring = bitstring[:-padding]

    heap = [HuffmanNode(b, f) for b, f in freq.items()]
    heapq.heapify(heap)
    while len(heap) > 1:
        l, r = heapq.heappop(heap), heapq.heappop(heap)
        node = HuffmanNode(None, l.freq + r.freq, l, r)
        heapq.heappush(heap, node)
    root = heap[0]

    result = bytearray()
    node = root
    for bit in bitstring:
        node = node.left if bit == "0" else node.right
        if node.byte is not None:
            result.append(node.byte)
            node = root
    return bytes(result)

# ---------------- AES Encryption ----------------
def aes_encrypt(data: bytes, password: str) -> bytes:
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return salt + cipher.nonce + tag + ciphertext

def aes_decrypt(enc_data: bytes, password: str) -> bytes:
    salt, nonce, tag, ciphertext = enc_data[:16], enc_data[16:32], enc_data[32:48], enc_data[48:]
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# ---------------- WAV Steganography (4 LSB max) ----------------
def embed_payload_in_wav(cover_path, payload, out_path, bits_per_sample=4):
    with wave.open(cover_path, "rb") as w:
        nframes, nchannels = w.getnframes(), w.getnchannels()
        sampwidth, framerate = w.getsampwidth(), w.getframerate()
        raw = w.readframes(nframes)

    if sampwidth != 2:
        raise ValueError("Only 16-bit PCM WAV supported.")
    samples = np.frombuffer(raw, dtype=np.int16).copy()
    total_samples = len(samples)

    header = struct.pack(">I", len(payload))
    full = header + payload
    bitstr = "".join(f"{b:08b}" for b in full)
    capacity = total_samples * bits_per_sample

    if len(bitstr) > capacity:
        raise ValueError(f"❌ Payload too large. Need {len(bitstr)} bits, capacity {capacity} bits.")

    mask = (1 << bits_per_sample) - 1
    for i, bit_chunk_start in enumerate(range(0, len(bitstr), bits_per_sample)):
        chunk = bitstr[bit_chunk_start:bit_chunk_start+bits_per_sample].ljust(bits_per_sample, "0")
        samples[i] = (samples[i] & ~mask) | int(chunk, 2)

    with wave.open(out_path, "wb") as w:
        w.setnchannels(nchannels)
        w.setsampwidth(sampwidth)
        w.setframerate(framerate)
        w.writeframes(samples.tobytes())

def extract_payload_from_wav(stego_path, bits_per_sample=4):
    with wave.open(stego_path, "rb") as w:
        nframes, nchannels = w.getnframes(), w.getnchannels()
        sampwidth = w.getsampwidth()
        raw = w.readframes(nframes)
    samples = np.frombuffer(raw, dtype=np.int16)
    mask = (1 << bits_per_sample) - 1

    bits = "".join(bin(s & mask)[2:].zfill(bits_per_sample) for s in samples)
    payload_len = int(bits[:32], 2)
    payload_bits = bits[32:32+payload_len*8]
    payload_bytes = bytes(int(payload_bits[i:i+8], 2) for i in range(0, len(payload_bits), 8))
    return payload_bytes

# ---------------- Main Steg Class ----------------
class ImageAudioSteg:
    def encrypt_image_into_audio(self, cover_wav, secret_image, out_path, password, bits_per_sample=4):
        # Read image
        img = Image.open(secret_image).convert("RGB")
        original_size = img.size

        # Convert to bytes
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        img_bytes = buf.getvalue()

        # Get audio capacity
        with wave.open(cover_wav, "rb") as w:
            nframes, nchannels = w.getnframes(), w.getnchannels()
            capacity_bytes = (nframes * nchannels * bits_per_sample) // 8

        # Compress+Encrypt+Pack (with metadata)
        comp = huffman_compress(img_bytes)
        enc = aes_encrypt(comp, password)
        data = pickle.dumps({"original_size": original_size, "enc": enc})

        # Auto-resize loop
        while len(data) > capacity_bytes:
            w, h = img.size
            img = img.resize((int(w*0.8), int(h*0.8)))
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            img_bytes = buf.getvalue()
            comp = huffman_compress(img_bytes)
            enc = aes_encrypt(comp, password)
            data = pickle.dumps({"original_size": original_size, "enc": enc})
            if min(img.size) < 64:
                raise ValueError("Even after resizing, image too large for this audio.")

        embed_payload_in_wav(cover_wav, data, out_path, bits_per_sample)
        print(f"✅ Image embedded (auto-resized to {img.size}) in {out_path}")

    def decrypt_image_from_audio(self, stego_path, out_image, password, bits_per_sample=4):
        payload = extract_payload_from_wav(stego_path, bits_per_sample)
        obj = pickle.loads(payload)
        enc, original_size = obj["enc"], obj["original_size"]
        dec = aes_decrypt(enc, password)
        decompressed = huffman_decompress(dec)

        img = Image.open(io.BytesIO(decompressed)).convert("RGB")
        img = img.resize(original_size)
        img.save(out_image)
        print(f"✅ Image recovered and resized back to original {original_size} → {out_image}")
