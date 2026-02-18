# ================================================================
# 🔊 Secure Multi-Audio Steganography (Menu Driven)
# Author: Akshit x GPT-5
# Features:
# - AES-256 (EAX) authenticated encryption (PBKDF2 key)
# - zlib compression
# - Multi-file splitting (automatically distribute payload)
# - 1-bit-per-byte LSB embedding
# - Menu-driven interface (encode / decode)
# ================================================================

import os
import struct
import zlib
import wave
from typing import List
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes


# ----------------- Constants -----------------
PBKDF2_ITERS = 200_000
SALT_LEN = 16
NONCE_LEN = 16
TAG_LEN = 16


# ----------------- Crypto Helpers -----------------
def _derive_key(password: str, salt: bytes) -> bytes:
    return PBKDF2(password.encode("utf-8"), salt, dkLen=32, count=PBKDF2_ITERS, hmac_hash_module=SHA256)


def encrypt_payload(plaintext_bytes: bytes, password: str) -> bytes:
    salt = get_random_bytes(SALT_LEN)
    key = _derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
    return salt + cipher.nonce + tag + ciphertext


def decrypt_payload(blob: bytes, password: str) -> bytes:
    salt = blob[:SALT_LEN]
    nonce = blob[SALT_LEN:SALT_LEN + NONCE_LEN]
    tag = blob[SALT_LEN + NONCE_LEN:SALT_LEN + NONCE_LEN + TAG_LEN]
    ciphertext = blob[SALT_LEN + NONCE_LEN + TAG_LEN:]
    key = _derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


# ----------------- Bit Conversion Helpers -----------------
def bytes_to_bitstr(b: bytes) -> str:
    return ''.join(f"{byte:08b}" for byte in b)


def bitstr_to_bytes(s: str) -> bytes:
    s = s[:len(s) - (len(s) % 8)]
    return bytes(int(s[i:i + 8], 2) for i in range(0, len(s), 8))


# ----------------- Audio Helpers -----------------
def audio_capacity_bits(wav_path: str) -> int:
    with wave.open(wav_path, "rb") as w:
        frames = w.readframes(w.getnframes())
    return len(frames)


def _embed_bytes_to_wav(cover_path: str, payload_bytes: bytes, out_path: str):
    with wave.open(cover_path, "rb") as w:
        params = w.getparams()
        frames = bytearray(w.readframes(w.getnframes()))

    payload_len = len(payload_bytes)
    header = struct.pack(">I", payload_len)
    full = header + payload_bytes
    bits = bytes_to_bitstr(full)

    if len(bits) > len(frames):
        raise ValueError("Payload too large for this audio file.")

    for i, bit in enumerate(bits):
        frames[i] = (frames[i] & 0xFE) | int(bit)

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with wave.open(out_path, "wb") as wout:
        wout.setparams(params)
        wout.writeframes(bytes(frames))


def _extract_bytes_from_wav(stego_path: str) -> bytes:
    with wave.open(stego_path, "rb") as w:
        frames = bytearray(w.readframes(w.getnframes()))

    header_bits = ''.join(str(frames[i] & 1) for i in range(32))
    header_bytes = bitstr_to_bytes(header_bits)
    payload_len = struct.unpack(">I", header_bytes)[0]
    total_bits = 32 + (payload_len * 8)

    if total_bits > len(frames):
        raise ValueError("Stego file truncated or corrupted.")

    payload_bits = ''.join(str(frames[i] & 1) for i in range(32, total_bits))
    return bitstr_to_bytes(payload_bits)


# ----------------- Multi-file Logic -----------------
def encode_multi_audio(audio_paths: List[str], message: str, output_folder: str, password: str) -> List[str]:
    plaintext_bytes = message.encode("utf-8")
    compressed = zlib.compress(plaintext_bytes)
    encrypted_blob = encrypt_payload(compressed, password)

    capacities = []
    for p in audio_paths:
        bits = audio_capacity_bits(p)
        usable_bytes = (bits - 32) // 8
        capacities.append(max(0, usable_bytes))

    total_capacity = sum(capacities)
    if len(encrypted_blob) > total_capacity:
        raise ValueError("Message too large for provided audios.")

    chunks, offset = [], 0
    for cap in capacities:
        take = min(cap, len(encrypted_blob) - offset)
        chunks.append(encrypted_blob[offset: offset + take])
        offset += take

    out_paths = []
    for i, (cover, chunk) in enumerate(zip(audio_paths, chunks)):
        base = os.path.splitext(os.path.basename(cover))[0]
        out_name = f"{base}_stego_part{i + 1}.wav"
        out_path = os.path.join(output_folder, out_name)
        _embed_bytes_to_wav(cover, chunk, out_path)
        out_paths.append(out_path)

    return out_paths


def decode_multi_audio(stego_paths: List[str], password: str) -> str:
    parts = [_extract_bytes_from_wav(p) for p in stego_paths]
    combined = b"".join(parts)
    decrypted = decrypt_payload(combined, password)
    decompressed = zlib.decompress(decrypted)
    return decompressed.decode("utf-8", errors="replace")


# ----------------- Menu-driven Main -----------------
def main():
    print("\n🔊 SECURE MULTI-AUDIO STEGANOGRAPHY SYSTEM 🔐")
    print("=============================================")
    print("1️⃣  Encrypt & Hide Message in Audio Files")
    print("2️⃣  Decrypt & Reveal Message")
    print("3️⃣  Exit")
    print("=============================================")

    choice = input("👉 Enter your choice (1/2/3): ").strip()

    if choice == "1":
        paths = input("\n🎵 Enter audio file paths (comma separated): ").split(",")
        paths = [p.strip() for p in paths if p.strip()]
        if not paths:
            print("❌ No audio paths provided.")
            return

        message = input("\n✉️  Enter your secret message: ")
        password = input("🔑 Enter password (used for AES encryption): ")
        output_folder = input("📂 Enter output folder path: ").strip() or "Results"

        try:
            print("\n🔧 Processing...")
            stego_files = encode_multi_audio(paths, message, output_folder, password)
            print("\n✅ Encoding successful! Saved stego files:")
            for f in stego_files:
                print("   →", f)
        except Exception as e:
            print("❌ Error during encoding:", e)

    elif choice == "2":
        paths = input("\n🎧 Enter stego audio file paths (comma separated): ").split(",")
        paths = [p.strip() for p in paths if p.strip()]
        password = input("🔑 Enter password for decryption: ")

        try:
            print("\n🕵️ Extracting...")
            message = decode_multi_audio(paths, password)
            print("\n📜 Hidden Message Recovered Successfully:")
            print("=============================================")
            print(message)
            print("=============================================")
        except Exception as e:
            print("❌ Error during decoding:", e)

    elif choice == "3":
        print("👋 Exiting program.")
        return
    else:
        print("❌ Invalid choice. Please select 1, 2, or 3.")


if __name__ == "__main__":
    while True:
        main()
        again = input("\n🔁 Do you want to perform another operation? (y/n): ").strip().lower()
        if again != 'y':
            print("\n👋 Goodbye!")
            break
