# ============================================================
# VideoImage_AutoResize.py
# Secure Video → Image Steganography (AES-GCM + Huffman + Auto-Resize)
# ============================================================
import os
import io
import struct
import pickle
from collections import Counter
import heapq
from math import ceil

from PIL import Image
import numpy as np
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# ================= Huffman (same stable implementation) =================
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
    if not heap:
        return pickle.dumps(({}, b""))
    while len(heap) > 1:
        l, r = heapq.heappop(heap), heapq.heappop(heap)
        heapq.heappush(heap, HuffmanNode(None, l.freq + r.freq, l, r))
    codes = {}
    def assign(node, code):
        if node.byte is not None:
            codes[node.byte] = code
        else:
            assign(node.left, code + "0")
            assign(node.right, code + "1")
    assign(heap[0], "")
    encoded = "".join(codes[b] for b in data)
    padding = (8 - len(encoded) % 8) % 8
    encoded += "0" * padding
    out = bytes([padding]) + bytes(int(encoded[i:i+8], 2) for i in range(0, len(encoded), 8))
    return pickle.dumps((freq, out))

def huffman_decompress(packed: bytes) -> bytes:
    freq, out = pickle.loads(packed)
    if not freq:
        return b""
    padding = out[0]
    bitstring = "".join(f"{byte:08b}" for byte in out[1:])
    if padding:
        bitstring = bitstring[:-padding]
    heap = [HuffmanNode(b, f) for b, f in freq.items()]
    heapq.heapify(heap)
    while len(heap) > 1:
        l, r = heapq.heappop(heap), heapq.heappop(heap)
        heapq.heappush(heap, HuffmanNode(None, l.freq + r.freq, l, r))
    root = heap[0]
    result = bytearray()
    node = root
    for bit in bitstring:
        node = node.left if bit == "0" else node.right
        if node.byte is not None:
            result.append(node.byte)
            node = root
    return bytes(result)

# ================= AES-GCM =================
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

# ================= Utility: ensure uint8 array =================
def load_image_as_uint8(path, mode="RGB"):
    img = Image.open(path).convert(mode)
    arr = np.array(img, dtype=np.uint8)
    return img, arr

# ================= Embedding with auto-resize =================
def embed_video_in_image(cover_img_path, video_path, output_path, password,
                         max_attempts=20, scale_step=1.2, max_dim=12000):
    # Read video bytes
    with open(video_path, "rb") as f:
        video_bytes = f.read()

    # Compress + Encrypt
    comp = huffman_compress(video_bytes)
    enc = aes_encrypt(comp, password)

    # Build payload: 8-byte big-endian length + encrypted bytes
    payload_len = len(enc)
    header = struct.pack(">Q", payload_len)   # allows very large payloads
    payload = header + enc
    total_bits_needed = len(payload) * 8

    # Load cover image
    img, arr = load_image_as_uint8(cover_img_path, mode="RGB")
    w, h = img.size
    flat = arr.flatten()
    capacity = flat.size  # 1 bit per element (LSB)

    attempts = 0
    while total_bits_needed > capacity:
        attempts += 1
        if attempts > max_attempts:
            raise ValueError("❌ Cannot fit payload: reached maximum resize attempts.")
        # Increase dimensions
        new_w = int(w * scale_step)
        new_h = int(h * scale_step)
        if new_w > max_dim or new_h > max_dim:
            raise ValueError(f"❌ Reached maximum image dimension limit ({max_dim}). Cannot fit payload.")
        print(f"⚠️  Increasing image size {w}x{h} → {new_w}x{new_h} to accommodate payload...")
        img = img.resize((new_w, new_h))   # PIL resizing
        w, h = img.size
        arr = np.array(img, dtype=np.uint8)
        flat = arr.flatten()
        capacity = flat.size

    # Now embed payload bits into LSBs of flat (safe uint8 operations)
    # We'll write sequentially per bit without making huge strings.

    flat = flat.astype(np.uint8)  # ensure dtype
    write_idx = 0
    # iterate bytes then bits
    for b in payload:
        for bitpos in range(7, -1, -1):
            bit = (b >> bitpos) & 1
            flat[write_idx] = (int(flat[write_idx]) & ~1) | int(bit)
            write_idx += 1

    # Reconstruct and save PNG (PNG is lossless)
    stego_arr = flat.reshape(arr.shape)
    stego_img = Image.fromarray(stego_arr.astype(np.uint8), mode="RGB")
    stego_img.save(output_path, format="PNG")
    print(f"✅ Video embedded successfully into {output_path} (final size: {w}x{h})")

# ================= Extraction =================
def extract_video_from_image(stego_img_path, output_video_path, password):
    img = Image.open(stego_img_path).convert("RGB")
    arr = np.array(img, dtype=np.uint8).flatten()

    # read first 8 bytes (64 bits) header to get payload length
    # collect first 64 bits
    if arr.size < 64:
        raise ValueError("Stego image too small or corrupted (no header).")

    header_bytes = bytearray()
    idx = 0
    for _ in range(8):
        byte = 0
        for _ in range(8):
            bit = int(arr[idx]) & 1
            byte = (byte << 1) | bit
            idx += 1
        header_bytes.append(byte)
    payload_len = struct.unpack(">Q", bytes(header_bytes))[0]

    total_bytes = 8 + payload_len
    total_bits = total_bytes * 8

    if arr.size < total_bits:
        raise ValueError("Stego image does not contain the full payload (truncated).")

    # read remaining bytes
    payload = bytearray(header_bytes)  # start with header
    while len(payload) < total_bytes:
        byte = 0
        for _ in range(8):
            bit = int(arr[idx]) & 1
            byte = (byte << 1) | bit
            idx += 1
        payload.append(byte)

    enc = bytes(payload[8:])  # encrypted compressed data
    try:
        dec = aes_decrypt(enc, password)
        decompressed = huffman_decompress(dec)
    except Exception as e:
        raise ValueError(f"Decryption/decompression failed: {e}")

    with open(output_video_path, "wb") as f:
        f.write(decompressed)
    print(f"✅ Video extracted -> {output_video_path}")

# ================= Menu =================
def main():
    print("\n🎥 Secure Video → Image Steganography (AES-GCM + Huffman + Auto-Resize)")
    while True:
        print("\n1) Embed Video into Image")
        print("2) Extract Video from Image")
        print("3) Exit")
        ch = input("Choose (1-3): ").strip()
        try:
            if ch == "1":
                cover = input("Enter cover image path: ").strip()
                video = input("Enter secret video file (.mp4/.avi): ").strip()
                out = input("Enter output stego image path (e.g., stego.png): ").strip()
                pwd = input("Enter encryption password: ").strip()
                embed_video_in_image(cover, video, out, pwd)
            elif ch == "2":
                stego = input("Enter stego image path: ").strip()
                outv = input("Enter output video path (e.g., recovered.mp4): ").strip()
                pwd = input("Enter password used during embedding: ").strip()
                extract_video_from_image(stego, outv, pwd)
            elif ch == "3":
                print("👋 Bye.")
                break
            else:
                print("❌ Invalid choice.")
        except Exception as e:
            print("⚠️ Error:", e)

if __name__ == "__main__":
    main()
