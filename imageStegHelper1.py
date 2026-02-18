# =======================================================
# imageStegHelper.py
# =======================================================

import os
import pickle
import struct
import math
import numpy as np
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from collections import Counter
import heapq

# ---------------- Huffman ----------------
class HuffmanNode:
    def __init__(self, byte=None, freq=0, left=None, right=None):
        self.byte = byte
        self.freq = freq
        self.left = left
        self.right = right
    def __lt__(self, other):
        return self.freq < other.freq

def build_huffman_code(data_bytes):
    freq = Counter(data_bytes)
    heap = []
    counter = 0
    for b, f in freq.items():
        node = HuffmanNode(byte=b, freq=f)
        heap.append((f, counter, node))
        counter += 1
    heapq.heapify(heap)
    while len(heap) > 1:
        f1, c1, n1 = heapq.heappop(heap)
        f2, c2, n2 = heapq.heappop(heap)
        merged = HuffmanNode(None, f1 + f2, n1, n2)
        heapq.heappush(heap, (merged.freq, counter, merged))
        counter += 1
    root = heap[0][2]
    codes = {}
    def generate_codes(node, prefix=""):
        if node is None:
            return
        if node.byte is not None:
            codes[bytes([node.byte])] = prefix or "0"
            return
        generate_codes(node.left, prefix + "0")
        generate_codes(node.right, prefix + "1")
    generate_codes(root)
    return codes

def huffman_encode(data_bytes):
    codes = build_huffman_code(data_bytes)
    bitstring = "".join(codes[bytes([b])] for b in data_bytes)
    b_out = bytearray()
    for i in range(0, len(bitstring), 8):
        chunk = bitstring[i:i+8].ljust(8, "0")
        b_out.append(int(chunk, 2))
    return bytes(b_out), pickle.dumps(codes)

def huffman_decode(encoded_bytes, codebook_pickle):
    codes = pickle.loads(codebook_pickle)
    inv = {v: k for k, v in codes.items()}
    bitstring = "".join(f"{b:08b}" for b in encoded_bytes)
    cur = ""
    out = bytearray()
    for bit in bitstring:
        cur += bit
        if cur in inv:
            out.extend(inv[cur])
            cur = ""
    return bytes(out)

# ---------------- AES ----------------
def derive_key(password, salt):
    return PBKDF2(password.encode(), salt, dkLen=32, count=200000)

def aes_encrypt(data, password):
    salt = get_random_bytes(16)
    key = derive_key(password, salt)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len]) * pad_len
    ciphertext = cipher.encrypt(data)
    return salt + iv + ciphertext

def aes_decrypt(data, password):
    if len(data) < 32:
        raise ValueError("Encrypted data too short.")
    salt = data[:16]
    iv = data[16:32]
    ciphertext = data[32:]
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = cipher.decrypt(ciphertext)
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Incorrect password or corrupted data (bad padding).")
    return padded[:-pad_len]

# ---------------- Bit helpers ----------------
def bytes_to_bits(data):
    for b in data:
        for i in range(7, -1, -1):
            yield (b >> i) & 1

def bits_to_bytes(bits):
    b, acc, cnt = bytearray(), 0, 0
    for bit in bits:
        acc = (acc << 1) | bit
        cnt += 1
        if cnt == 8:
            b.append(acc)
            acc, cnt = 0, 0
    if cnt > 0:
        b.append(acc << (8 - cnt))
    return bytes(b)

# ---------------- Steganography Core ----------------
class ImageSteg:

    def _embed_bytes_in_image(self, cover_img, payload, out_path):
        """
        Safely embed `payload` bytes into a single cover image using 1 LSB per RGB channel.
        Uses signed int dtype during bit ops to avoid OverflowError, then casts back to uint8.
        """
        arr = np.array(cover_img.convert("RGB"), dtype=np.int32)
        h, w, _ = arr.shape
        total_bits = (len(payload) + 4) * 8  # 4-byte length header + payload
        capacity = h * w * 3
        if total_bits > capacity:
            raise ValueError(f"Payload too large for this cover image! Capacity bits: {capacity}, required: {total_bits}")

        header = struct.pack(">I", len(payload))
        full = header + payload
        flat = arr.reshape(-1, 3)
        bit_iter = bytes_to_bits(full)

        for bit_index in range(total_bits):
            pix_idx = bit_index // 3
            ch = bit_index % 3
            bit = next(bit_iter)
            # use 0xFE to clear LSB safely (no negative intermediate)
            flat[pix_idx, ch] = (flat[pix_idx, ch] & 0xFE) | bit

        arr_uint8 = np.clip(flat.reshape(h, w, 3), 0, 255).astype(np.uint8)
        Image.fromarray(arr_uint8).save(out_path)

    def _extract_bytes_from_image(self, stego_img):
        """
        Extract payload bytes from a single stego image (reverse of _embed_bytes_in_image).
        """
        arr = np.array(stego_img.convert("RGB"), dtype=np.uint8).reshape(-1, 3)
        # first 32 bits -> length header
        header_bits = [arr[i // 3, i % 3] & 1 for i in range(32)]
        header = bits_to_bytes(header_bits)
        length = struct.unpack(">I", header)[0]
        if length == 0:
            return b""
        total_bits = length * 8
        data_bits = [arr[i // 3, i % 3] & 1 for i in range(32, 32 + total_bits)]
        return bits_to_bytes(data_bits)

    # ---------------- Multi-image Embed ----------------
    def encrypt_image_in_multiple_covers(self, cover_paths, secret_path, output_folder, password):
        """
        Hides the secret file across multiple cover images.
        cover_paths: list of file paths to cover images (order matters for extraction)
        secret_path: path to secret file (bytes will be hidden)
        output_folder: directory to save stego parts
        password: AES password
        Returns list of saved stego file paths.
        """
        os.makedirs(output_folder, exist_ok=True)
        with open(secret_path, "rb") as f:
            secret_data = f.read()

        # Huffman compress and pickle codebook
        comp_bytes, codebook_pickle = huffman_encode(secret_data)
        payload_plain = pickle.dumps((comp_bytes, codebook_pickle))

        # AES encrypt full payload
        encrypted = aes_encrypt(payload_plain, password)

        num_covers = len(cover_paths)
        if num_covers == 0:
            raise ValueError("No cover images provided.")

        # split encrypted into `num_covers` chunks (evenly, last chunk may be smaller)
        chunk_size = math.ceil(len(encrypted) / num_covers)
        chunks = [encrypted[i:i + chunk_size] for i in range(0, len(encrypted), chunk_size)]

        # If there are fewer chunks than covers (unlikely), pad with empty bytes
        while len(chunks) < num_covers:
            chunks.append(b"")

        stego_paths = []
        for i, cover in enumerate(cover_paths):
            chunk = chunks[i] if i < len(chunks) else b""
            out = os.path.join(output_folder, f"stego_part_{i+1}.png")
            # embed chunk into this cover; will raise ValueError if chunk too large for that cover
            self._embed_bytes_in_image(Image.open(cover), chunk, out)
            stego_paths.append(out)
            print(f"✅ Embedded part {i+1} in {out}  (bytes embedded: {len(chunk)})")
        return stego_paths

    def decrypt_image_from_multiple_covers(self, stego_paths, output_secret, password):
        """
        Reconstructs the encrypted payload from multiple stego parts, decrypts, and writes the recovered secret file.
        stego_paths: list of stego images in the same order used for embedding
        output_secret: path to write the recovered secret file
        password: AES password
        """
        parts = []
        for path in stego_paths:
            chunk = self._extract_bytes_from_image(Image.open(path))
            parts.append(chunk)
            print(f"📥 Extracted {len(chunk)} bytes from {path}")

        combined = b"".join(parts)
        if not combined:
            raise ValueError("No data extracted from provided stego images.")

        # AES decrypt
        decrypted = aes_decrypt(combined, password)

        # Unpickle and Huffman decode
        comp_bytes, codebook_pickle = pickle.loads(decrypted)
        recovered = huffman_decode(comp_bytes, codebook_pickle)

        with open(output_secret, "wb") as f:
            f.write(recovered)
        print(f"\n✅ Secret image reconstructed successfully: {output_secret}")
        return output_secret
