"""
Enhanced text steganography using Zero-Width Characters (ZWCs)
Features:
 - AES-256 encryption (EAX mode) with PBKDF2-derived key (password)
 - zlib compression
 - SHA-256 checksum
 - Randomized ZWC mapping based on password (per-session)
 - Embedding into words with fallback to character-level embedding
 - Uses a 32-bit payload-length header, so no fragile end-marker is required
"""

import os
import zlib
import base64
import hashlib
import math
import random
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# ---------------------------------------
# Configuration
# ---------------------------------------
DEFAULT_BITS_PER_SLOT = 12  # how many bits we embed per "slot" (word or char boundary)
SALT_LEN = 16
PBKDF2_ITER = 200_000
KEY_LEN = 32  # AES-256
NONCE_LEN = 16  # for AES EAX
ZWCS_POOL = [
    '\u200C',  # ZWNJ
    '\u202C',  # PDF
    '\u202D',  # LRO
    '\u200E',  # LRM
    '\u200B',  # ZWSP
    '\u2060',  # Word Joiner
    '\u200F',  # RLM
]


# ---------------------------------------
# Helper crypto/compress functions
# ---------------------------------------
def _derive_key(password: str, salt: bytes) -> bytes:
    return PBKDF2(password.encode('utf-8'), salt, dkLen=KEY_LEN, count=PBKDF2_ITER, hmac_hash_module=hashlib.sha256)


def encrypt_payload(plaintext_bytes: bytes, password: str) -> bytes:
    """
    Returns: base64-encoded blob containing salt + nonce + tag + ciphertext
    """
    salt = get_random_bytes(SALT_LEN)
    from Crypto.Hash import SHA256
    key = PBKDF2(password, salt, dkLen=32, count=100000, hmac_hash_module=SHA256)

    cipher = AES.new(key, AES.MODE_EAX, nonce=get_random_bytes(NONCE_LEN))
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
    blob = salt + cipher.nonce + tag + ciphertext
    return base64.b64encode(blob)


def decrypt_payload(b64_blob: bytes, password: str) -> bytes:
    blob = base64.b64decode(b64_blob)
    salt = blob[:SALT_LEN]
    nonce = blob[SALT_LEN:SALT_LEN + NONCE_LEN]
    tag = blob[SALT_LEN + NONCE_LEN:SALT_LEN + NONCE_LEN + 16]  # EAX tag 16 bytes
    ciphertext = blob[SALT_LEN + NONCE_LEN + 16:]
    from Crypto.Hash import SHA256
    key = PBKDF2(password, salt, dkLen=32, count=100000, hmac_hash_module=SHA256)

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext


# ---------------------------------------
# Binary & ZWC helpers
# ---------------------------------------
def bytes_to_binary_str(b: bytes) -> str:
    return ''.join(format(byte, '08b') for byte in b)


def binary_str_to_bytes(s: str) -> bytes:
    # pad to 8 multiple
    if len(s) % 8:
        s = s + '0' * (8 - (len(s) % 8))
    out = bytearray()
    for i in range(0, len(s), 8):
        out.append(int(s[i:i + 8], 2))
    return bytes(out)


def make_zwc_mapping(password: str):
    """Deterministically choose 4 ZWCs from pool using password-derived seed."""
    seed = int(hashlib.sha256(password.encode('utf-8')).hexdigest(), 16) & ((1 << 32) - 1)
    rnd = random.Random(seed)
    chosen = rnd.sample(ZWCS_POOL, 4)
    bits_to_zwc = {"00": chosen[0], "01": chosen[1], "10": chosen[2], "11": chosen[3]}
    zwc_to_bits = {v: k for k, v in bits_to_zwc.items()}
    return bits_to_zwc, zwc_to_bits


# ---------------------------------------
# Encode / Decode (public)
# ---------------------------------------
def txt_encode(message: str, cover_file_path: str, password: str,
               bits_per_slot: int = DEFAULT_BITS_PER_SLOT) -> str:
    """
    Creates a stego text file by embedding 'message' inside the text at cover_file_path.

    Returns path to stego file.
    """
    if not os.path.exists(cover_file_path):
        raise FileNotFoundError("Cover file not found: " + cover_file_path)

    # 1) compress
    compressed = zlib.compress(message.encode('utf-8'))

    # 2) checksum (first 16 hex chars) — store for integrity (we keep raw bytes for verification)
    checksum = hashlib.sha256(compressed).digest()  # 32 bytes

    # 3) payload layout: [4 bytes length][checksum (32 bytes)][compressed data]
    payload_len = len(compressed)
    len_bytes = payload_len.to_bytes(4, byteorder='big')
    payload = len_bytes + checksum + compressed

    # 4) encrypt payload with password
    encrypted_b64 = encrypt_payload(payload, password)  # bytes
    encrypted_bytes = encrypted_b64  # we're embedding base64 bytes for portability

    # 5) convert to binary string
    binary_data = bytes_to_binary_str(encrypted_bytes)

    # 6) prepare ZWC mapping (randomized per password)
    bits_to_zwc, _ = make_zwc_mapping(password)

    # 7) read cover text and decide embedding slots
    with open(cover_file_path, 'r', encoding='utf-8') as f:
        text = f.read()

    words = text.split()  # simple splitting; keeps original words count
    total_slots = len(words)
    bits_needed = len(binary_data)
    bits_per_word = bits_per_slot

    # estimate capacity
    capacity = total_slots * bits_per_word
    use_char_level = False
    char_insert_positions = []  # list of (word_index, char_idx) tuples if needed

    if capacity < bits_needed:
        # fallback: try to use character-level insertion positions
        # Build a list of possible insertion positions (between characters) across words
        for wi, w in enumerate(words):
            # allow insertion positions between characters and at start/end of word
            for ci in range(len(w) + 1):
                char_insert_positions.append((wi, ci))
        total_slots = len(char_insert_positions)
        capacity = total_slots * bits_per_word
        if capacity < bits_needed:
            raise ValueError(f"Cover too small. Capacity {capacity} bits < needed {bits_needed} bits even after char-level fallback.")
        use_char_level = True

    # 8) split binary into 2-bit pairs and map to ZWCs (we'll attach groups of bits_per_word bits per slot)
    # Build slot strings (ZWC sequences) for each slot
    slot_zwc_sequences = []
    i = 0
    while i < len(binary_data):
        chunk = binary_data[i:i + bits_per_word]
        seq = ""
        for j in range(0, len(chunk), 2):
            pair = chunk[j:j + 2]
            if len(pair) < 2:
                pair = pair.ljust(2, '0')
            seq += bits_to_zwc[pair]
        slot_zwc_sequences.append(seq)
        i += bits_per_word

    # Pad the rest of slots with empty strings
    while len(slot_zwc_sequences) < (len(char_insert_positions) if use_char_level else len(words)):
        slot_zwc_sequences.append("")

    # 9) construct stego text
    if not use_char_level:
        # attach sequences after words
        stego_words = []
        for idx, w in enumerate(words):
            seq = slot_zwc_sequences[idx] if idx < len(slot_zwc_sequences) else ""
            stego_words.append(w + seq)
        stego_text = " ".join(stego_words)
    else:
        # Insert at character-level: we'll reconstruct each word as list of chars and inject ZWCs where required
        word_chars = [list(w) for w in words]
        # prepare mapping from (wi, ci) -> seq
        mapping_positions = {}
        for pos_idx, seq in enumerate(slot_zwc_sequences):
            wi, ci = char_insert_positions[pos_idx]
            mapping_positions.setdefault(wi, []).append((ci, seq))
        # reconstruct words with inserted ZWCs
        stego_words = []
        for wi, chars in enumerate(word_chars):
            inserts = mapping_positions.get(wi, [])
            # sort inserts by char index ascending
            inserts.sort(key=lambda x: x[0])
            rebuilt = []
            last = 0
            for ci, seq in inserts:
                # append chars from last to ci
                if ci > len(chars):
                    ci = len(chars)
                rebuilt.extend(chars[last:ci])
                # insert sequence
                rebuilt.append(seq)
                last = ci
            # append remainder
            rebuilt.extend(chars[last:])
            stego_words.append("".join(rebuilt))
        stego_text = " ".join(stego_words)

    # 10) save to result folder
    filename = os.path.splitext(os.path.basename(cover_file_path))[0]
    result_folder = os.path.join(os.path.dirname(__file__), "..", "backend", "Result_files")
    os.makedirs(result_folder, exist_ok=True)
    stego_path = os.path.join(result_folder, f"{filename}_stegano.txt")
    with open(stego_path, 'w', encoding='utf-8') as out:
        out.write(stego_text)

    print(f"✅ Encoded stego file: {stego_path}  (embedded {len(binary_data)} bits)")
    return stego_path


def txt_decode(stego_file_path: str, password: str, bits_per_slot: int = DEFAULT_BITS_PER_SLOT) -> str:
    """
    Reads a stego text file and attempts to extract and decrypt the hidden message.
    Returns the decoded plaintext message (str).
    """
    if not os.path.exists(stego_file_path):
        raise FileNotFoundError("Stego file not found: " + stego_file_path)

    # load and split
    with open(stego_file_path, 'r', encoding='utf-8') as f:
        text = f.read()
    words = text.split()

    # prepare zwc reverse mapping using password
    _, zwc_to_bits = make_zwc_mapping(password)

    # Collect all zero-width characters in the text in the same slot order used by the encoder.
    # We'll attempt both word-level and char-level extraction:
    binary_bits = []

    # First -- assume word-level embedding: after each word, collect any ZWC characters appended
    for w in words:
        # gather zwc chars
        collected = ""
        # scan characters after the normal visible characters at end of word
        # To be conservative: check whole word for zwc chars
        for ch in w:
            if ch in zwc_to_bits:
                collected += zwc_to_bits[ch]
        binary_bits.append(collected)

    # Concatenate collected bits into a single binary string
    binary_str = "".join(binary_bits)

    # If binary_str is empty or very short, try char-level extraction:
    if len(binary_str) < 8:
        # char-level: scan original text for ZWCs in order of appearance
        zwc_seq = []
        for ch in text:
            if ch in zwc_to_bits:
                zwc_seq.append(zwc_to_bits[ch])
        binary_str = "".join(zwc_seq)

    if not binary_str:
        raise ValueError("❌ No hidden data found (no ZWCs detected).")

    # Now we have a long stream of 0/1 characters but grouped as 2-bit strings (because zwc_to_bits yields '00' etc.)
    # If the mapping created '00' strings concatenated, we currently have collected strings like '001011...'
    # We need to convert that to a binary string that represents bytes from base64.
    # Our encoder used bytes_to_binary_str on base64(bytes). So now we should reassemble into bytes every 8 bits.

    # binary_str currently is sequence of '00','01','10','11' concatenated: already a valid bitstring.
    # Trim trailing bits to multiple of 8
    total_bits = len(binary_str)
    if total_bits % 8 != 0:
        # discard trailing bits that don't fit a full byte
        binary_str = binary_str[:total_bits - (total_bits % 8)]

    # convert to bytes
    try:
        extracted_bytes = binary_str_to_bytes(binary_str)
    except Exception as e:
        raise ValueError("Failed to convert extracted binary to bytes: " + str(e))

    # extracted_bytes is supposed to be base64-encoded blob (salt+nonce+tag+ciphertext)
    # Strip nulls or non-base64 trailing bytes by attempting base64 decode until success
    # In many cases extracted_bytes directly equals base64-encoded bytes, so:
    try:
        # attempt to trim leading/trailing whitespace/newline that might have been included
        b64_blob = extracted_bytes.strip()
        # decrypt
        payload = decrypt_payload(b64_blob, password)
    except Exception as e:
        # If decryption fails, give an informative message
        raise ValueError("Decryption failed. Wrong password or corrupted data. (" + str(e) + ")")

    # payload: [4 bytes length][checksum 32 bytes][compressed data]
    if len(payload) < 4 + 32:
        raise ValueError("Payload too short / corrupted after decryption.")

    payload_len = int.from_bytes(payload[:4], byteorder='big')
    checksum = payload[4:4 + 32]
    compressed = payload[4 + 32:]

    # verify length
    if payload_len != len(compressed):
        # truncated or corrupted possibly — still attempt to decompress if possible, but warn
        print("⚠️ Warning: declared payload length mismatch (declared {} != actual {}).".format(payload_len, len(compressed)))

    # verify checksum
    actual_checksum = hashlib.sha256(compressed).digest()
    if actual_checksum != checksum:
        raise ValueError("❌ Checksum mismatch: data corrupted or wrong password.")

    # decompress
    try:
        plaintext_bytes = zlib.decompress(compressed)
    except Exception as e:
        raise ValueError("Decompression failed: " + str(e))

    decoded_text = plaintext_bytes.decode('utf-8', errors='replace')
    print("✅ Decoded message:", decoded_text)
    return decoded_text


# ---------------------------------------
# Example usage (main test)
# ---------------------------------------
if __name__ == "__main__":
    # adjust these paths & password for your environment
    message = "hie my name is Akshit and this should decode completely!"
    cover_file = r"D:\Major Project 1\STEGANOGRAPHY_HIDDEN_HARBOR\Sample_cover_files\SampleText.txt"
    password = "strong_password_here"

    try:
        stego = txt_encode(message, cover_file, password)
        print("Stego file:", stego)
        decoded = txt_decode(stego, password)
        print("Final Decoded Output:", decoded)
    except Exception as e:
        print("Error:", str(e))
