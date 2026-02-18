import os
import math
import struct
import numpy as np
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# ---------------- AES Encryption ----------------
def derive_key(password, salt):
    return PBKDF2(password.encode(), salt, dkLen=32, count=150000)

def aes_encrypt(data, password):
    salt = get_random_bytes(16)
    iv = get_random_bytes(16)
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pad_len = 16 - len(data) % 16
    data += bytes([pad_len]) * pad_len
    ciphertext = cipher.encrypt(data)
    return salt + iv + ciphertext

def aes_decrypt(data, password):
    salt, iv, ciphertext = data[:16], data[16:32], data[32:]
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = cipher.decrypt(ciphertext)
    pad_len = padded[-1]
    return padded[:-pad_len]

# ---------------- Bit Helper Functions ----------------
def bytes_to_bits(data):
    return ''.join(format(b, '08b') for b in data)

def bits_to_bytes(bitstring):
    return bytes(int(bitstring[i:i+8], 2) for i in range(0, len(bitstring), 8))

# =======================================================
# 🔹 Main Class
# =======================================================
class AdaptiveTextSteg:
    def __init__(self):
        pass

    def _embed_bits(self, img_array, bitstream):
        flat = img_array.flatten()
        if len(bitstream) > len(flat):
            raise ValueError("Not enough pixels to embed all bits.")
        for i, bit in enumerate(bitstream):
            flat[i] = (flat[i] & 0xFE) | int(bit)
        return flat.reshape(img_array.shape)

    def _extract_bits(self, img_array, total_bits):
        flat = img_array.flatten()
        return ''.join(str(flat[i] & 1) for i in range(total_bits))

    # ---------- Adaptive Embedding ----------
    def encrypt_text_in_images(self, image_paths, message, password, output_folder="Results"):
        os.makedirs(output_folder, exist_ok=True)

        # Encrypt message
        encrypted = aes_encrypt(message.encode(), password)
        ciphertext_bits = bytes_to_bits(encrypted)

        # Prefix 32-bit header for ciphertext length
        header = struct.pack(">I", len(ciphertext_bits))
        header_bits = bytes_to_bits(header)
        full_bits = header_bits + ciphertext_bits

        print(f"🔐 Total bits to embed: {len(full_bits)}")

        remaining_bits = full_bits
        stego_paths = []

        for i, path in enumerate(image_paths):
            img = Image.open(path)
            arr = np.array(img.convert("RGB"))
            capacity = arr.size

            print(f"📷 Using {os.path.basename(path)} | Capacity: {capacity} bits")

            if len(remaining_bits) > capacity:
                part_bits = remaining_bits[:capacity]
                remaining_bits = remaining_bits[capacity:]
            else:
                part_bits = remaining_bits
                remaining_bits = ""

            modified = self._embed_bits(arr, part_bits)
            save_path = os.path.join(output_folder, f"stego_part_{i+1}.png")
            Image.fromarray(modified.astype(np.uint8)).save(save_path)
            stego_paths.append(save_path)
            print(f"✅ Embedded {len(part_bits)} bits → {save_path}")

            if not remaining_bits:
                break

        if remaining_bits:
            print("⚠️ Not enough capacity! Add more images.")
        else:
            print("✅ Message successfully embedded.")

        return stego_paths

    def decrypt_text_from_images(self, stego_paths, password):
        """Extract the full encrypted message (with known header)."""
        bitstream = ""
        for path in stego_paths:
            img = Image.open(path)
            arr = np.array(img.convert("RGB"))
            bitstream += ''.join(str(x & 1) for x in arr.flatten())

        # Extract header → message length
        header_bits = bitstream[:32]
        header_bytes = bits_to_bytes(header_bits)
        msg_length = struct.unpack(">I", header_bytes)[0]

        print(f"🧩 Detected message length: {msg_length} bits")

        cipher_bits = bitstream[32:32 + msg_length]
        cipher_bytes = bits_to_bytes(cipher_bits)

        decrypted = aes_decrypt(cipher_bytes, password)
        return decrypted.decode(errors="ignore")

# =======================================================
# 🧠 CLI Interface
# =======================================================
if __name__ == "__main__":
    steg = AdaptiveTextSteg()
    print("🔹 Adaptive Text Steganography System")
    mode = input("1️⃣ Encrypt Text  2️⃣ Decrypt Text  → Enter choice: ")

    if mode == "1":
        images = input("Enter image paths (comma separated): ").split(",")
        msg = input("Enter your secret message: ")
        pwd = input("Enter password: ")
        out_folder = input("Enter output folder (default=Results): ") or "Results"
        steg.encrypt_text_in_images([p.strip() for p in images], msg, pwd, out_folder)

    elif mode == "2":
        images = input("Enter stego image paths (comma separated): ").split(",")
        pwd = input("Enter password: ")
        print("🕵️ Extracting...")
        result = steg.decrypt_text_from_images([p.strip() for p in images], pwd)
        print("📜 Decrypted Message:", result)
