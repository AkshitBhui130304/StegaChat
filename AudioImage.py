# ============================================================
# AudioImageStegano_AutoResize.py
# Secure Audio → Image Steganography (AES + Huffman + Auto-Resize)
# ============================================================

import os
import io
import struct
import numpy as np
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from collections import Counter
import heapq
import pickle

# ============================================================
# Huffman Compression / Decompression
# ============================================================
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
        heapq.heappush(heap, HuffmanNode(None, l.freq + r.freq, l, r))
    root = heap[0]

    codes = {}
    def assign(node, code):
        if node.byte is not None:
            codes[node.byte] = code
        else:
            assign(node.left, code + "0")
            assign(node.right, code + "1")
    assign(root, "")

    encoded = "".join(codes[b] for b in data)
    padding = 8 - len(encoded) % 8
    encoded += "0" * padding
    out = bytes([padding]) + bytes(int(encoded[i:i+8], 2) for i in range(0, len(encoded), 8))
    return pickle.dumps((freq, out))

def huffman_decompress(packed: bytes) -> bytes:
    freq, out = pickle.loads(packed)
    padding = out[0]
    bits = "".join(f"{b:08b}" for b in out[1:])[:-padding]
    heap = [HuffmanNode(b, f) for b, f in freq.items()]
    heapq.heapify(heap)
    while len(heap) > 1:
        l, r = heapq.heappop(heap), heapq.heappop(heap)
        heapq.heappush(heap, HuffmanNode(None, l.freq + r.freq, l, r))
    root = heap[0]

    node = root
    result = bytearray()
    for bit in bits:
        node = node.left if bit == "0" else node.right
        if node.byte is not None:
            result.append(node.byte)
            node = root
    return bytes(result)

# ============================================================
# AES Encryption
# ============================================================
def aes_encrypt(data: bytes, password: str) -> bytes:
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return salt + cipher.nonce + tag + ciphertext

def aes_decrypt(enc: bytes, password: str) -> bytes:
    salt, nonce, tag, ciphertext = enc[:16], enc[16:32], enc[32:48], enc[48:]
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# ============================================================
# Steganography Core
# ============================================================
def embed_audio_in_image(cover_image, secret_audio, out_image, password):
    img = Image.open(cover_image).convert("RGB")
    data = np.array(img, dtype=np.uint8)
    flat = data.flatten()

    # Read, compress, encrypt audio
    with open(secret_audio, "rb") as f:
        audio_data = f.read()
    comp = huffman_compress(audio_data)
    enc = aes_encrypt(comp, password)
    header = struct.pack(">I", len(enc))
    payload = header + enc

    bitstring = "".join(f"{b:08b}" for b in payload)
    capacity = len(flat)

    # Auto-resize if audio doesn't fit
    resize_attempts = 0
    while len(bitstring) > capacity:
        resize_attempts += 1
        w, h = img.size
        if min(w, h) < 64:
            raise ValueError("❌ Even after resizing, audio too large for this image.")
        new_w, new_h = int(w * 1.2), int(h * 1.2)
        print(f"⚠️  Resizing image from {w}x{h} → {new_w}x{new_h} to fit audio...")
        img = img.resize((new_w, new_h))
        data = np.array(img, dtype=np.uint8)
        flat = data.flatten()
        capacity = len(flat)

    # Embed bits into LSBs
    for i, bit in enumerate(bitstring):
        flat[i] = (int(flat[i]) & ~1) | int(bit)

    stego = flat.reshape(data.shape)
    Image.fromarray(stego.astype(np.uint8)).save(out_image)
    print(f"✅ Audio embedded successfully → {out_image}")

def extract_audio_from_image(stego_image, out_audio, password):
    img = Image.open(stego_image).convert("RGB")
    data = np.array(img, dtype=np.uint8).flatten()
    bits = "".join(str(d & 1) for d in data)

    payload_len = int(bits[:32], 2)
    total_bits = (payload_len + 4) * 8
    payload = bytes(int(bits[i:i+8], 2) for i in range(0, total_bits, 8))

    enc = payload[4:]
    dec = aes_decrypt(enc, password)
    decompressed = huffman_decompress(dec)

    with open(out_audio, "wb") as f:
        f.write(decompressed)
    print(f"✅ Audio extracted successfully → {out_audio}")

# ============================================================
# Menu Interface
# ============================================================
def main():
    while True:
        print("\n🎵 Secure Audio ↔ Image Steganography (AES + Huffman + Auto-Resize)")
        print("1) Embed Audio into Image")
        print("2) Extract Audio from Image")
        print("3) Exit")
        choice = input("Choose (1-3): ").strip()

        try:
            if choice == "1":
                cover = input("Enter cover image path: ").strip()
                audio = input("Enter secret audio file (.wav/.mp3): ").strip()
                out = input("Enter output stego image path (e.g., steg.png): ").strip()
                password = input("Enter encryption password: ").strip()
                embed_audio_in_image(cover, audio, out, password)

            elif choice == "2":
                stego = input("Enter stego image path: ").strip()
                out_audio = input("Enter output audio filename (e.g., hidden.wav): ").strip()
                password = input("Enter password used during encryption: ").strip()
                extract_audio_from_image(stego, out_audio, password)

            elif choice == "3":
                print("👋 Exiting...")
                break
            else:
                print("❌ Invalid choice. Try again.")
        except Exception as e:
            print(f"⚠️ Error: {e}")

if __name__ == "__main__":
    main()
