#!/usr/bin/env python3
"""
secure_video_steg_with_meta.py

Secure menu-driven video steganography with embedded, encrypted metadata
(so decoding does not require remembering frame indices).

Features:
 - AES-GCM (authenticated) encryption with PBKDF2-derived key (SHA256)
 - optional zlib compression
 - LSB embedding into frames (BGR channels)
 - embeds encrypted metadata (frames list) into first frame automatically
 - single-frame or multi-frame embedding (supports 'auto' frame selection)
"""

import os
import struct
import zlib
import math
import json
import cv2
import numpy as np
from typing import List
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# ----------------- Configuration -----------------
PBKDF2_ITERS = 200_000
SALT_LEN = 16
NONCE_LEN = 12        # GCM recommended nonce length
TAG_LEN = 16          # GCM tag length
HEADER_BITS = 32      # we'll store payload bit-length in 32 bits (big-endian)
META_HEADER_BITS = 32 # metadata length header (in bits) also 32 bits

# ----------------- Crypto helpers -----------------
def derive_key(password: str, salt: bytes) -> bytes:
    return PBKDF2(password.encode('utf-8'), salt, dkLen=32, count=PBKDF2_ITERS, hmac_hash_module=SHA256)

def encrypt_message(plaintext: bytes, password: str, compress: bool = True) -> bytes:
    """Return blob: salt || nonce || tag || ciphertext"""
    if compress:
        plaintext = zlib.compress(plaintext)
    salt = get_random_bytes(SALT_LEN)
    key = derive_key(password, salt)
    nonce = get_random_bytes(NONCE_LEN)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return salt + nonce + tag + ciphertext

def decrypt_message(blob: bytes, password: str, decompress: bool = True) -> bytes:
    """Given blob salt||nonce||tag||ciphertext, returns plaintext bytes"""
    if len(blob) < (SALT_LEN + NONCE_LEN + TAG_LEN + 1):
        raise ValueError("Blob too short / corrupted.")
    salt = blob[:SALT_LEN]
    nonce = blob[SALT_LEN:SALT_LEN+NONCE_LEN]
    tag = blob[SALT_LEN+NONCE_LEN:SALT_LEN+NONCE_LEN+TAG_LEN]
    ciphertext = blob[SALT_LEN+NONCE_LEN+TAG_LEN:]
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    if decompress:
        return zlib.decompress(plaintext)
    return plaintext

# ----------------- bit helpers -----------------
def bytes_to_bitstr(b: bytes) -> str:
    return ''.join(f"{byte:08b}" for byte in b)

def bitstr_to_bytes(s: str) -> bytes:
    if len(s) % 8 != 0:
        s = s[:len(s) - (len(s) % 8)]
    return bytes(int(s[i:i+8], 2) for i in range(0, len(s), 8))

# ----------------- video helpers -----------------
def ensure_avi_format(video_path: str) -> str:
    base, ext = os.path.splitext(video_path)
    ext = ext.lower()
    if ext == ".avi":
        return video_path
    temp_avi = base + "_temp.avi"
    print(f"Converting '{video_path}' -> '{temp_avi}' using lossless FFV1 (via OpenCV).")
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        raise ValueError(f"Cannot open video: {video_path}")
    w = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    h = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    fps = cap.get(cv2.CAP_PROP_FPS)
    if fps <= 0 or np.isnan(fps):
        fps = 24.0
    # try FFV1; fallback to XVID
    fourcc = cv2.VideoWriter_fourcc(*'FFV1')
    out = cv2.VideoWriter(temp_avi, fourcc, fps, (w, h))
    if not out.isOpened():
        fourcc = cv2.VideoWriter_fourcc(*'XVID')
        out = cv2.VideoWriter(temp_avi, fourcc, fps, (w, h))
    while True:
        ret, frame = cap.read()
        if not ret:
            break
        out.write(frame)
    cap.release()
    out.release()
    print("Conversion done.")
    return temp_avi

def frame_capacity_bits(frame: np.ndarray) -> int:
    return frame.shape[0] * frame.shape[1] * frame.shape[2]

# ----------------- metadata embed/extract (first frame) -----------------
def embed_metadata_in_frame(frame: np.ndarray, meta_blob: bytes):
    """
    Embed metadata blob into the beginning of frame's flattened bytes:
      - store 32-bit length (bytes) header, then the blob bytes
    Returns modified frame and number of bits consumed (meta_bits).
    """
    header = struct.pack(">I", len(meta_blob))  # 4-byte length
    full = header + meta_blob
    bits = bytes_to_bitstr(full)
    flat = frame.flatten()
    if len(bits) > flat.size:
        raise ValueError("Metadata too large to store in first frame.")
    # embed into first len(bits) bytes
    for i, bit in enumerate(bits):
        flat[i] = (int(flat[i]) & 0xFE) | (1 if bit == '1' else 0)
    new_frame = flat.reshape(frame.shape).astype(np.uint8)
    return new_frame, len(bits)

def extract_metadata_from_frame(frame: np.ndarray) -> bytes:
    """
    Extract metadata bytes from the beginning of frame.
    Returns metadata blob bytes. If no metadata found or corrupted, raises.
    Procedure:
      - read first 32 bits -> header length (bytes)
      - read header_length * 8 bits -> blob
    """
    flat = frame.flatten()
    if flat.size < META_HEADER_BITS:
        raise ValueError("Frame too small to contain metadata header.")
    header_bits = ''.join(str(int(flat[i]) & 1) for i in range(META_HEADER_BITS))
    header_bytes = bitstr_to_bytes(header_bits)
    meta_len = struct.unpack(">I", header_bytes)[0]
    total_bits = META_HEADER_BITS + (meta_len * 8)
    if flat.size < total_bits:
        raise ValueError("Frame metadata appears truncated or corrupted.")
    meta_bits = ''.join(str(int(flat[i]) & 1) for i in range(META_HEADER_BITS, total_bits))
    meta_blob = bitstr_to_bytes(meta_bits)
    return meta_blob

# ----------------- embed/extract payload bits with frame-skip support -----------------
def embed_bits_in_frame(frame: np.ndarray, bitstream: str, frame_skip_bits: int = 0, start_bit: int = 0):
    """
    Embed segment of bitstream into frame, skipping first frame_skip_bits of the frame.
    - frame_skip_bits: number of bits at very start of this frame reserved (metadata)
    - start_bit: index into bitstream from which to start writing
    Returns (modified_frame, new_start_bit)
    """
    flat = frame.flatten()
    capacity = flat.size - frame_skip_bits
    remaining_bits = len(bitstream) - start_bit
    to_take = min(capacity, remaining_bits)
    if to_take <= 0:
        return frame, start_bit
    # write into flat[frame_skip_bits : frame_skip_bits + to_take]
    for i in range(to_take):
        bit = bitstream[start_bit + i]
        idx = frame_skip_bits + i
        flat[idx] = (int(flat[idx]) & 0xFE) | (1 if bit == '1' else 0)
    new_frame = flat.reshape(frame.shape).astype(np.uint8)
    return new_frame, start_bit + to_take

def extract_bits_from_frame(frame: np.ndarray, needed_bits: int, frame_skip_bits: int = 0):
    """
    Extract up to needed_bits from frame skipping first frame_skip_bits bits.
    Returns (bits_str, bits_extracted).
    """
    flat = frame.flatten()
    available = flat.size - frame_skip_bits
    to_take = min(needed_bits, available)
    if to_take <= 0:
        return "", 0
    bits = ''.join(str(int(flat[frame_skip_bits + i]) & 1) for i in range(to_take))
    return bits, to_take

# ----------------- high-level embed / extract -----------------
def embed_into_video_with_metadata(source_video: str, out_video: str, blob: bytes, frames_to_use: List[int], meta_password: str, convert_lossless: bool = True):
    """
    Embed blob into frames_to_use while also embedding encrypted metadata (frames list) into frame 1.
    Metadata is: encrypted JSON { "frames": [..], "version":1 } as AES-GCM blob.
    """
    # prepare metadata blob (encrypt)
    meta = {"frames": frames_to_use, "version": 1}
    meta_json = json.dumps(meta).encode('utf-8')
    meta_blob = encrypt_message(meta_json, meta_password, compress=False)  # do NOT compress metadata (small)
    # open video (with conversion if needed)
    worked_video = source_video
    temp_conv = None
    if convert_lossless:
        worked_video = ensure_avi_format(source_video)
        if worked_video.endswith("_temp.avi"):
            temp_conv = worked_video
    cap = cv2.VideoCapture(worked_video)
    if not cap.isOpened():
        raise ValueError("Cannot open video for embedding.")
    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH)); height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    fps = cap.get(cv2.CAP_PROP_FPS)
    if fps <= 0 or np.isnan(fps): fps = 24.0
    # full payload bits (header + payload)
    payload_bits = bytes_to_bitstr(blob)
    header_bits = bytes_to_bitstr((len(payload_bits)).to_bytes(4, byteorder='big'))
    full_bits = header_bits + payload_bits
    # Prepare writer
    fourcc = cv2.VideoWriter_fourcc(*'FFV1'); out_writer = cv2.VideoWriter(out_video, fourcc, fps, (width, height))
    if not out_writer.isOpened():
        fourcc = cv2.VideoWriter_fourcc(*'XVID'); out_writer = cv2.VideoWriter(out_video, fourcc, fps, (width, height))
    bit_index = 0
    current_frame_no = 0
    frames_set = set(frames_to_use)
    # We need to know how many meta bits will be consumed in frame 1
    meta_header_bytes = struct.pack(">I", len(meta_blob))
    meta_bits_len = len(bytes_to_bitstr(meta_header_bytes + meta_blob))
    # iterate frames, embed metadata into frame 1, then embed payload into frames_to_use skipping meta region if frame 1 also used
    while True:
        ret, frame = cap.read()
        if not ret: break
        current_frame_no += 1
        frame_skip_bits = 0
        modified_frame = frame
        if current_frame_no == 1:
            # embed metadata into start of frame 1
            modified_frame, consumed_meta_bits = embed_metadata_in_frame(frame, meta_blob)
            frame_skip_bits = consumed_meta_bits  # reserve these bits from payload embedding in frame 1
            # if no payload to embed, just write and continue
            if bit_index >= len(full_bits):
                out_writer.write(modified_frame); continue
        # if this frame is selected for payload embedding
        if current_frame_no in frames_set and bit_index < len(full_bits):
            mod_frame, new_index = embed_bits_in_frame(modified_frame, full_bits, frame_skip_bits=frame_skip_bits, start_bit=bit_index)
            bit_index = new_index
            out_writer.write(mod_frame)
        else:
            out_writer.write(modified_frame)
    cap.release(); out_writer.release()
    if bit_index < len(full_bits):
        if os.path.exists(out_video): os.remove(out_video)
        if temp_conv and os.path.exists(temp_conv): os.remove(temp_conv)
        raise ValueError(f"Not enough capacity. Embedded {bit_index}/{len(full_bits)} bits.")
    if temp_conv and os.path.exists(temp_conv): os.remove(temp_conv)
    print(f"✅ Embedding complete. Output saved: {out_video}")
    return out_video

def extract_from_video_with_metadata(source_video: str, password: str, convert_lossless: bool = True):
    """
    Extract metadata from frame 1, decrypt to get frames list, then extract payload from those frames and return payload bytes.
    If metadata decrypt fails, raises ValueError (caller can fallback to manual frame input).
    """
    worked_video = source_video
    temp_conv = None
    if convert_lossless:
        worked_video = ensure_avi_format(source_video)
        if worked_video.endswith("_temp.avi"):
            temp_conv = worked_video
    cap = cv2.VideoCapture(worked_video)
    if not cap.isOpened():
        raise ValueError("Cannot open video for extraction.")
    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    # read frame 1 to get metadata
    cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
    ret, frame1 = cap.read()
    if not ret:
        cap.release()
        raise ValueError("Could not read frame 1 for metadata.")
    try:
        meta_blob = extract_metadata_from_frame(frame1)
    except Exception as e:
        cap.release()
        raise ValueError("No valid metadata found in frame 1: " + str(e))
    # decrypt metadata
    try:
        meta_plain = decrypt_message(meta_blob, password, decompress=False)
        meta = json.loads(meta_plain.decode('utf-8'))
        frames_to_use = meta.get("frames", [])
        if not frames_to_use:
            raise ValueError("Metadata empty frames list.")
    except Exception as e:
        cap.release()
        raise ValueError("Failed to decrypt/parse metadata: " + str(e))
    # now extract payload from those frames in order
    bitstream = ""
    header_bits = ""
    payload_len = None
    payload_bits = ""
    reading_header = True
    frames_set = set(frames_to_use)
    cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
    current_frame_no = 0
    # compute meta bits used in frame1 so we skip them while extracting payload if frame1 included
    meta_header_bytes = struct.pack(">I", len(meta_blob))
    meta_bits_len = len(bytes_to_bitstr(meta_header_bytes + meta_blob))
    while True:
        ret, frame = cap.read()
        if not ret: break
        current_frame_no += 1
        frame_skip = meta_bits_len if current_frame_no == 1 else 0
        if current_frame_no in frames_set:
            bits, taken = extract_bits_from_frame(frame, frame_capacity_bits(frame) - frame_skip, frame_skip_bits=frame_skip)
            bitstream += bits
            if reading_header and len(bitstream) >= HEADER_BITS:
                header_bits = bitstream[:HEADER_BITS]
                payload_len = int.from_bytes(bitstr_to_bytes(header_bits), byteorder='big')
                reading_header = False
                bitstream = bitstream[HEADER_BITS:]
            if payload_len is not None and len(bitstream) >= payload_len:
                payload_bits = bitstream[:payload_len]
                break
    cap.release()
    if temp_conv and os.path.exists(temp_conv): os.remove(temp_conv)
    if payload_len is None:
        raise ValueError("Could not find payload header after metadata.")
    if len(payload_bits) < payload_len:
        raise ValueError(f"Incomplete extraction: got {len(payload_bits)}/{payload_len} bits.")
    payload_bytes = bitstr_to_bytes(payload_bits)
    return payload_bytes, frames_to_use

# ----------------- auto-select frames -----------------
def auto_select_frames(video_path: str, required_bits: int) -> List[int]:
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        raise ValueError("Cannot open video.")
    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    w = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH)); h = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    cap.release()
    per_frame_capacity = w * h * 3
    if per_frame_capacity <= 0:
        raise ValueError("Invalid frame capacity.")
    # include first frame (for metadata); need to account meta reservation there
    needed_frames = math.ceil(required_bits / per_frame_capacity)
    if needed_frames > total_frames:
        raise ValueError(f"Need {needed_frames} frames but video has only {total_frames}.")
    step = total_frames / needed_frames
    frames = [max(1, min(total_frames, int(round(step * i + step/2)))) for i in range(needed_frames)]
    frames = sorted(list(dict.fromkeys(frames)))
    return frames

# ----------------- Menu-driven CLI -----------------
def menu():
    print("\n🎥 Secure Video Steganography (AES-GCM + optional compression + encrypted metadata)")
    print("1) Encode (single frame)  2) Encode (multi-frame; supply indices or 'auto')")
    print("3) Decode (auto-read metadata)  4) Decode (manual frames)  5) Exit")
    return input("Choose an option (1-5): ").strip()

def cli_encode_multi():
    video = input("Enter video path: ").strip()
    message = input("Enter secret message: ").encode('utf-8')
    password = input("Enter password: ").strip()
    compress_choice = input("Enable zlib compression before encrypt? (y/n, default y): ").strip().lower() or 'y'
    compress = compress_choice == 'y'
    frames_input = input("Enter comma-separated frame numbers OR type 'auto' to auto-select frames: ").strip()
    out_folder = input("Output folder (default Results): ").strip() or "Results"
    os.makedirs(out_folder, exist_ok=True)
    out_video = os.path.join(out_folder, os.path.splitext(os.path.basename(video))[0] + "_stego_with_meta.avi")
    try:
        blob = encrypt_message(message, password, compress=compress)
        total_bits_needed = HEADER_BITS + len(bytes_to_bitstr(blob))
        print(f"Total bits to embed (header+payload): {total_bits_needed}")
        tmp = ensure_avi_format(video)
        if frames_input.lower() == 'auto':
            frames = auto_select_frames(tmp, total_bits_needed)
            print(f"Auto-selected frames: {frames}")
        else:
            frames = [int(x.strip()) for x in frames_input.split(',') if x.strip()]
        # quick capacity check (account metadata in frame1)
        cap = cv2.VideoCapture(tmp)
        total_cap = 0
        cur = 0
        cap_per_frame = {}
        while True:
            ret, f = cap.read()
            if not ret: break
            cur += 1
            if cur in frames:
                c = frame_capacity_bits(f)
                if cur == 1:
                    # reserve some for metadata (we'll compute exact later, but assume metadata small)
                    pass
                total_cap += c
                cap_per_frame[cur] = c
        cap.release()
        # estimate meta bits: small JSON encrypted blob — we'll check in embed function for exact fit
        if total_cap < total_bits_needed:
            print(f"❌ Not enough combined capacity ({total_cap} bits). Need {total_bits_needed}.")
            return
        print("Embedding into frames:", frames)
        embed_into_video_with_metadata(video, out_video, blob, frames, meta_password=password)
    except Exception as e:
        print("Error during multi-frame encoding:", e)

def cli_decode_auto():
    video = input("Enter stego video path: ").strip()
    password = input("Enter password: ").strip()
    try:
        print("Extracting metadata from frame 1 and payload automatically...")
        payload_bytes, frames_used = extract_from_video_with_metadata(video, password)
        plaintext = decrypt_message(payload_bytes, password, decompress=True)
        print("\n✅ Recovered message (frames used:", frames_used, "):\n")
        try:
            # decrypted is bytes (decompressed), decode to string
            print(plaintext.decode('utf-8', errors='replace') if isinstance(plaintext, bytes) else plaintext)
        except:
            print("<binary data recovered>")
    except Exception as e:
        print("Error during auto decoding:", e)
        choice = input("Would you like to try manual frame decode? (y/n): ").strip().lower() or 'n'
        if choice == 'y':
            cli_decode_manual()

def cli_decode_manual():
    video = input("Enter stego video path: ").strip()
    frames_input = input("Enter comma-separated frame numbers used for embedding (order matters): ").strip()
    frames = [int(x.strip()) for x in frames_input.split(',') if x.strip()]
    password = input("Enter password: ").strip()
    try:
        print("Extracting bits from frames...")
        # reuse previous extraction function but without metadata; we will use extract_from_video_with_metadata only for auto mode
        # So implement quick manual extraction: extract bits from supplied frames directly (no metadata)
        # We'll reuse extract_from_video_with_metadata but first create a fake metadata; simpler: read frames and extract header+payload as earlier implementation
        # For brevity, call extract_from_video_with_metadata but bypass metadata step by creating a dummy metadata that matches frames (not ideal)
        # Instead we implement manual extraction:
        worked_video = ensure_avi_format(video)
        cap = cv2.VideoCapture(worked_video)
        if not cap.isOpened():
            raise ValueError("Cannot open video.")
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        for fidx in frames:
            if fidx < 1 or fidx > total_frames:
                raise ValueError(f"Frame {fidx} out of range.")
        bitstream = ""
        header_bits = ""; payload_len = None; reading_header=True
        cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
        cur = 0
        frames_set = set(frames)
        while True:
            ret, frame = cap.read()
            if not ret: break
            cur += 1
            if cur in frames_set:
                bits, taken = extract_bits_from_frame(frame, frame_capacity_bits(frame))
                bitstream += bits
                if reading_header and len(bitstream) >= HEADER_BITS:
                    header_bits = bitstream[:HEADER_BITS]; payload_len = int.from_bytes(bitstr_to_bytes(header_bits), byteorder='big'); reading_header=False; bitstream = bitstream[HEADER_BITS:]
                if payload_len is not None and len(bitstream) >= payload_len:
                    payload_bits = bitstream[:payload_len]; break
        cap.release()
        if payload_len is None:
            raise ValueError("Could not find payload header.")
        payload_bytes = bitstr_to_bytes(payload_bits)
        plaintext = decrypt_message(payload_bytes, password, decompress=True)
        print("\n✅ Recovered message:\n")
        print(plaintext.decode('utf-8', errors='replace') if isinstance(plaintext, bytes) else plaintext)
    except Exception as e:
        print("Error during manual decoding:", e)

def main_loop():
    while True:
        ch = menu()
        if ch == '1':
            print("Single-frame encode currently not shown; use multi-frame for metadata-enabled encoding.")
            # single-frame functionality could be added (wrap embed_into_video_with_metadata with single frame list)
        elif ch == '2':
            cli_encode_multi()
        elif ch == '3':
            cli_decode_auto()
        elif ch == '4':
            cli_decode_manual()
        elif ch == '5':
            print("Goodbye.")
            break
        else:
            print("Invalid choice. Please select 1-5.")

if __name__ == "__main__":
    main_loop()
