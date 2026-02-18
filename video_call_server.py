"""
Secure Multimedia Steganography Video Call — Ultra-low latency refactor.
- Media: WebRTC peer-to-peer (no server-side frame processing).
- Hidden messages: WebRTC DataChannel with client-side encryption (key from BB84).
- Server: signaling only (WebRTC offer/answer/ICE), BB84 key exchange, hybrid secure file, extract endpoint.
- No base64 media transport; no OpenCV on live path.
"""

import base64
import hashlib
import json
import os
import struct
import time
import uuid
import wave
import zlib
from flask import Flask, request, send_from_directory, Response
from flask_socketio import SocketIO, emit, join_room, leave_room
from engineio.payload import Payload

import call_stego
from bb84_module import run_bb84

# OpenCV/numpy only for extract endpoint (and hybrid if needed), not for live streaming
import cv2
import numpy as np

try:
    import eventlet  # noqa: F401
    _async_mode = "eventlet"
except ImportError:
    _async_mode = "threading"

# Monkey-patch eventlet so client disconnect (BrokenPipe/ConnectionReset) doesn't log tracebacks.
# Eventlet's write() is a closure that calls wfile.writelines/flush; we wrap those.
if _async_mode == "eventlet":
    import eventlet.wsgi as _eventlet_wsgi
    _orig_handle = _eventlet_wsgi.HttpProtocol.handle_one_response

    def _handle_one_response_safe(self):
        wfile = self.wfile
        _orig_writelines = wfile.writelines
        _orig_flush = wfile.flush

        def _safe_writelines(seq):
            try:
                _orig_writelines(seq)
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass

        def _safe_flush():
            try:
                _orig_flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass

        wfile.writelines = _safe_writelines
        wfile.flush = _safe_flush
        try:
            return _orig_handle(self)
        finally:
            wfile.writelines = _orig_writelines
            wfile.flush = _orig_flush

    _eventlet_wsgi.HttpProtocol.handle_one_response = _handle_one_response_safe

# No large frame payloads; keep moderate for signaling and extract/hybrid
Payload.max_decode_packet_size = 5 * 1024 * 1024  # 5 MB


def _log(msg):
    """Print to terminal so logs are visible when running the server."""
    import sys
    print("[STEGO]", msg, flush=True)
    sys.stdout.flush()


def _audio_cover_level(pcm_bytes):
    """Analyze PCM 16-bit LE mono; return has_signal, rms, db for logging."""
    if not pcm_bytes or len(pcm_bytes) < 2:
        return False, 0.0, -100.0
    raw = pcm_bytes[: (len(pcm_bytes) // 2) * 2]
    samples = np.frombuffer(raw, dtype=np.int16)
    n = len(samples)
    if n == 0:
        return False, 0.0, -100.0
    sum_sq = int(np.sum(samples.astype(np.int64) ** 2))
    rms = np.sqrt(sum_sq / n) / 32768.0
    max_abs = int(np.max(np.abs(samples)))
    db = -100.0 if rms <= 1e-7 else float(20 * np.log10(rms))
    db = max(-100.0, db)
    has_signal = max_abs >= 32 and rms >= 0.0005
    return bool(has_signal), float(rms), float(db)


def _float32_to_pcm16(audio_float32: np.ndarray) -> np.ndarray:
    """Convert float32 [-1, 1] to int16 PCM. No double-scaling."""
    audio_float32 = np.clip(audio_float32, -1.0, 1.0)
    return (audio_float32 * 32767).astype(np.int16)


def _adaptive_gain(samples: np.ndarray, target_rms: float = 0.05) -> np.ndarray:
    """
    Boost int16 PCM to target RMS (pre-embedding). Prevents clipping; max gain 8.0.
    Pipeline: raw capture -> adaptive_gain -> LSB embedding.
    """
    current_rms = np.sqrt(np.mean(samples.astype(np.float64) ** 2)) / 32767.0
    if current_rms < 1e-6:
        _log("[AUDIO DEBUG] RMS before gain: {:.6f} (silence, no gain)".format(current_rms))
        return samples
    gain = target_rms / current_rms
    gain = min(gain, 8.0)
    _log("[AUDIO DEBUG] RMS before gain: {:.6f}".format(current_rms))
    _log("[AUDIO DEBUG] Applied gain: {:.2f}".format(gain))
    boosted = samples.astype(np.float64) * gain
    boosted = np.clip(boosted, -32768, 32767)
    return boosted.astype(np.int16)


STEGO_DEBUG_AUDIO = os.environ.get("STEGO_DEBUG_AUDIO", "").strip().lower() in ("1", "true", "yes")


def _debug_audio_compare(original: np.ndarray, stego: np.ndarray, first_n: int = 200) -> None:
    """
    Bit-level comparison of original vs stego PCM. Run only when STEGO_DEBUG_AUDIO=1.
    Verifies LSB-only modification and prints stats.
    """
    n = min(first_n, len(original), len(stego))
    if n == 0:
        return
    changed = 0
    diffs = []
    non_lsb_changes = []
    for i in range(n):
        o = int(original[i]) & 0xFFFF
        s = int(stego[i]) & 0xFFFF
        if o >= 32768:
            o -= 65536
        if s >= 32768:
            s -= 65536
        orig_u16 = int(original[i]) & 0xFFFF
        stego_u16 = int(stego[i]) & 0xFFFF
        if orig_u16 != stego_u16:
            changed += 1
            d = abs(o - s)
            diffs.append(d)
            xor_bits = orig_u16 ^ stego_u16
            if xor_bits not in (0, 1):
                non_lsb_changes.append((i, orig_u16, stego_u16, xor_bits))
    _log("=== STEGO AUDIO DEBUG: original vs stego ===")
    _log("First {} samples:".format(n))
    for i in range(min(200, n)):
        o = int(original[i]) & 0xFFFF
        s = int(stego[i]) & 0xFFFF
        if o >= 32768:
            o -= 65536
        if s >= 32768:
            s -= 65536
        orig_u16 = int(original[i]) & 0xFFFF
        stego_u16 = int(stego[i]) & 0xFFFF
        xor_val = orig_u16 ^ stego_u16
        orig_bin = "{:016b}".format(orig_u16)
        stego_bin = "{:016b}".format(stego_u16)
        _log("  [{}] orig={:6d} stego={:6d}  orig_bin={} stego_bin={}  xor={}".format(
            i, o, s, orig_bin, stego_bin, xor_val))
    _log("--- Summary ---")
    _log("Samples changed: {} / {}".format(changed, n))
    if diffs:
        mean_abs = float(np.mean(diffs))
        max_diff = int(np.max(diffs))
        rms_diff = float(np.sqrt(np.mean(np.array(diffs, dtype=np.float64) ** 2)))
        _log("Mean absolute difference: {:.4f}".format(mean_abs))
        _log("Max difference: {}".format(max_diff))
        _log("RMS difference: {:.4f}".format(rms_diff))
        if mean_abs > 2:
            _log("*** WARNING: average difference > 2 (audible distortion likely) ***")
    else:
        _log("Mean absolute difference: 0 (no sample changes in first {})".format(n))
    if non_lsb_changes:
        _log("*** MORE THAN 1 BIT CHANGED in {} sample(s) (not LSB-only!) ***".format(len(non_lsb_changes)))
        for idx, ou, su, xor_b in non_lsb_changes[:20]:
            _log("  sample {}: orig_u16={} stego_u16={} xor_bits={:016b}".format(idx, ou, su, xor_b))
    else:
        if changed > 0:
            _log("LSB-only modification confirmed (all changes are 0 or 1).")


def _debug_audio_sparse_log(original: np.ndarray, stego: np.ndarray) -> None:
    """Log percentage modified, mean/max difference, and LSB-only confirmation over full arrays."""
    n = min(len(original), len(stego))
    if n == 0:
        return
    orig = original[:n].astype(np.int32)
    stg = stego[:n].astype(np.int32)
    diff = np.abs(orig - stg)
    changed_mask = orig != stg
    n_modified = int(np.sum(changed_mask))
    pct = 100.0 * n_modified / n
    mean_abs = float(np.mean(diff[changed_mask])) if n_modified else 0.0
    max_diff = int(np.max(diff)) if n else 0
    _log("Percentage of samples modified: {:.2f}%".format(pct))
    _log("Mean absolute difference: {:.4f}".format(mean_abs))
    _log("Max difference: {}".format(max_diff))
    if max_diff <= 1:
        _log("LSB-only modification confirmed (all diffs in {-1, 0, 1}).")
    else:
        _log("*** Not LSB-only: some diffs > 1 ***")


def _save_received_audio_wav(samples: np.ndarray, sample_rate: int) -> None:
    """Save PCM received from browser to Results/ for fidelity comparison. Uses client sample_rate."""
    try:
        project_dir = os.path.dirname(os.path.abspath(__file__))
        out_dir = os.path.join(project_dir, "Results")
        os.makedirs(out_dir, exist_ok=True)
        raw_path = os.path.join(out_dir, "raw_browser_recording.wav")
        recv_path = os.path.join(out_dir, "backend_received.wav")
        n = len(samples)
        if n == 0:
            return
        duration_sec = n / float(sample_rate) if sample_rate else 0
        arr = samples.astype(np.int16)
        for path in (raw_path, recv_path):
            with wave.open(path, "wb") as w:
                w.setnchannels(1)
                w.setsampwidth(2)
                w.setframerate(sample_rate)
                w.writeframes(arr.tobytes())
        _log("[AUDIO DEBUG] Saved received PCM: raw_browser_recording.wav, backend_received.wav")
        _log("[AUDIO DEBUG] Duration: {:.3f}s, sample_rate: {}, samples: {}".format(duration_sec, sample_rate, n))
    except Exception as e:
        _log("  (save received wav failed: {})".format(e))


def _debug_save_wav_and_difference(original: np.ndarray, stego: np.ndarray, sample_rate: int = 48000) -> None:
    """
    Save original and stego WAVs to project Results/ for comparison. Run when STEGO_DEBUG_AUDIO=1.
    difference = original - stego. If LSB-only, difference is in {-1, 0, 1} (noise-like).
    """
    try:
        project_dir = os.path.dirname(os.path.abspath(__file__))
        out_dir = os.path.join(project_dir, "Results")
        os.makedirs(out_dir, exist_ok=True)
        orig_path = os.path.join(out_dir, "original_audio.wav")
        stego_path = os.path.join(out_dir, "stego_audio.wav")
        diff_path = os.path.join(out_dir, "difference_audio.wav")
        n = min(len(original), len(stego))
        if n == 0:
            return
        orig = original[:n].astype(np.int16)
        stg = stego[:n].astype(np.int16)
        with wave.open(orig_path, "wb") as w:
            w.setnchannels(1)
            w.setsampwidth(2)
            w.setframerate(sample_rate)
            w.writeframes(orig.tobytes())
        with wave.open(stego_path, "wb") as w:
            w.setnchannels(1)
            w.setsampwidth(2)
            w.setframerate(sample_rate)
            w.writeframes(stg.tobytes())
        diff = orig.astype(np.int32) - stg.astype(np.int32)
        max_abs_diff = int(np.max(np.abs(diff)))
        diff_clip = np.clip(diff, -32767, 32767).astype(np.int16)
        with wave.open(diff_path, "wb") as w:
            w.setnchannels(1)
            w.setsampwidth(2)
            w.setframerate(sample_rate)
            w.writeframes(diff_clip.tobytes())
        duration_sec = n / float(sample_rate) if sample_rate else 0
        _log("=== WAV files saved (STEGO_DEBUG_AUDIO) ===")
        _log("  sample_rate: {}, duration: {:.3f}s".format(sample_rate, duration_sec))
        _log("  original_audio.wav  -> {}".format(orig_path))
        _log("  stego_audio.wav     -> {}".format(stego_path))
        _log("  difference_audio.wav (original - stego) -> {}".format(diff_path))
        _log("  max(|difference|) = {}".format(max_abs_diff))
        if max_abs_diff <= 1:
            _log("  -> Waveform difference is LSB-only (values -1,0,1) -> LSB embedding working.")
        else:
            _log("  *** Large amplitude in difference -> multiple bits changed (not LSB-only). ***")
    except Exception as e:
        _log("  (save wav failed: {})".format(e))


app = Flask(__name__, static_folder="static", template_folder="static")
app.config["SECRET_KEY"] = "stego-video-call-secret"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode=_async_mode, max_http_buffer_size=5 * 1024 * 1024)


def _wsgi_suppress_client_disconnect(wsgi_app):
    """Suppress BrokenPipeError/ConnectionResetError when client closes (e.g. browser cancels).
    Patch every possible write reference on the response object so eventlet uses safe_write."""
    def wrapper(environ, start_response):
        def safe_write(real_write):
            def _safe(data):
                try:
                    return real_write(data)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass
            return _safe

        def start_response_trap(status, headers, exc_info=None):
            real_write = start_response(status, headers, exc_info)
            safe = safe_write(real_write)
            # Patch the response object so eventlet's stored reference uses safe_write
            obj = getattr(real_write, "__self__", None)
            if obj is not None:
                for name in ("write", "_write", "send"):
                    if hasattr(obj, name):
                        setattr(obj, name, safe)
            # If eventlet uses the return value, return safe
            return safe

        return wsgi_app(environ, start_response_trap)
    return wrapper


app.wsgi_app = _wsgi_suppress_client_disconnect(app.wsgi_app)

# room_id -> { "sids": set, "key": bytes (AES), "key_bits": str, "modes": {} }
rooms = {}
# Streaming audio embed: (room_id, from_sid) -> { "buffer": bitstream, "stego_parts": [ndarray], "session_id": str, "chunk_index": int }
audio_embed_state = {}

# Hybrid transfer: file_id -> { "data": bytes, "expiry": float, "checksum": str, "filename": str }
secure_files = {}
HYBRID_EXPIRY_SEC = 600


def get_room(room_id):
    return rooms.get(room_id)


def _payload_to_raw(payload):
    """Normalize payload to raw bytes: accept base64 string or binary (bytes/list). Keeps transfer non-blocking."""
    if payload is None:
        return None
    if isinstance(payload, bytes):
        return payload
    if isinstance(payload, (list, tuple)):
        return bytes(payload)
    if isinstance(payload, str):
        return base64.b64decode(payload)
    return None


def ensure_room(room_id):
    if room_id not in rooms:
        rooms[room_id] = {"sids": set(), "key": None, "key_bits": None, "modes": {}}
    return rooms[room_id]


# Secret payload type byte: 0=text, 1=image, 2=audio, 3=video, 4=chunked, 5=hybrid token
SECRET_TYPE_TEXT = 0
SECRET_TYPE_IMAGE = 1
SECRET_TYPE_AUDIO = 2
SECRET_TYPE_VIDEO = 3
SECRET_TYPE_CHUNKED = 4
SECRET_TYPE_HYBRID = 5


def build_secret_bytes(data, key=None):
    """Build bytes to embed: text, file, or one chunk. For chunked, key is required."""
    secret = (data or {}).get("secret_message")
    payload_b64 = (data or {}).get("secret_payload")
    secret_type_str = (data or {}).get("secret_type", "text")
    chunk_session_id = (data or {}).get("chunk_session_id")
    chunk_index = (data or {}).get("chunk_index")
    total_chunks = (data or {}).get("total_chunks")
    chunk_file_type = (data or {}).get("chunk_file_type", "image")

    if payload_b64 and isinstance(payload_b64, str) and chunk_index is not None and total_chunks is not None and chunk_session_id is not None:
        raw_chunk = base64.b64decode(payload_b64)
        type_map = {"text": SECRET_TYPE_TEXT, "image": SECRET_TYPE_IMAGE, "audio": SECRET_TYPE_AUDIO, "video": SECRET_TYPE_VIDEO}
        ft = type_map.get(str(chunk_file_type).lower(), SECRET_TYPE_IMAGE)
        sid = chunk_session_id if isinstance(chunk_session_id, bytes) else (str(chunk_session_id).encode("utf-8") + b"\x00" * 4)[:4]
        if len(sid) < 4:
            sid = sid + b"\x00" * (4 - len(sid))
        sid = sid[:4]
        meta = bytes([SECRET_TYPE_CHUNKED]) + sid + struct.pack(">HH", int(chunk_index), int(total_chunks)) + bytes([ft])
        import zlib
        compressed = zlib.compress(raw_chunk, level=9)
        if key:
            encrypted = call_stego.encrypt_with_key(compressed, key)
            return meta + encrypted
        return None
    if payload_b64 and isinstance(payload_b64, str) and str(secret_type_str).lower() == "hybrid_token":
        raw = base64.b64decode(payload_b64)
        return bytes([SECRET_TYPE_HYBRID]) + raw
    if payload_b64 and isinstance(payload_b64, str):
        raw = base64.b64decode(payload_b64)
        type_map = {"text": SECRET_TYPE_TEXT, "image": SECRET_TYPE_IMAGE, "audio": SECRET_TYPE_AUDIO, "video": SECRET_TYPE_VIDEO}
        t = type_map.get(secret_type_str.lower(), SECRET_TYPE_TEXT)
        return bytes([t]) + raw
    if secret and isinstance(secret, str) and secret.strip():
        return bytes([SECRET_TYPE_TEXT]) + secret.strip().encode("utf-8")
    return None


def parse_extracted(blob, key=None):
    """Parse extracted bytes. Returns (message, secret_type, secret_payload_b64, chunk_info or None, hybrid_info or None)."""
    if not blob or len(blob) < 1:
        return None, None, None, None, None
    t = blob[0]
    content = blob[1:]
    if t == SECRET_TYPE_HYBRID and len(content) >= 32 and key:
        try:
            dec = call_stego.decrypt_with_key(content, key)
            info = json.loads(dec.decode("utf-8"))
            return None, "hybrid", None, None, {
                "file_id": info.get("fileId"),
                "checksum": info.get("checksum"),
                "expiry_time": info.get("expiryTime"),
                "filename": info.get("filename", "download"),
            }
        except Exception:
            return None, None, None, None, None
    if t == SECRET_TYPE_TEXT:
        try:
            return content.decode("utf-8", errors="replace"), None, None, None, None
        except Exception:
            return None, None, None, None, None
    if t == SECRET_TYPE_CHUNKED and len(content) >= 9 and key:
        sid = content[:4]
        idx, total = struct.unpack(">HH", content[4:8])
        ft_byte = content[8]
        enc = content[9:]
        type_names = {SECRET_TYPE_IMAGE: "image", SECRET_TYPE_AUDIO: "audio", SECRET_TYPE_VIDEO: "video"}
        ft_name = type_names.get(ft_byte, "image")
        try:
            dec = call_stego.decrypt_with_key(enc, key)
            chunk_raw = zlib.decompress(dec)
            return None, "chunk", base64.b64encode(chunk_raw).decode("ascii"), {
                "chunk_session_id": base64.b64encode(sid).decode("ascii"),
                "chunk_index": idx,
                "total_chunks": total,
                "file_type": ft_name,
            }, None
        except Exception:
            return None, None, None, None, None
    type_names = {SECRET_TYPE_IMAGE: "image", SECRET_TYPE_AUDIO: "audio", SECRET_TYPE_VIDEO: "video"}
    name = type_names.get(t)
    if name and content:
        return None, name, base64.b64encode(content).decode("ascii"), None, None
    return None, None, None, None, None


def run_bb84_and_set_key(room_id):
    r = rooms.get(room_id)
    if not r or r.get("key") is not None:
        return r.get("key_bits")
    result = run_bb84(n_qubits=256, error_threshold=0.11, eve=False)
    if not result.get("accepted"):
        return None
    key_bits = result["final_key"]
    r["key_bits"] = key_bits
    r["key"] = call_stego.bb84_key_to_aes_key(key_bits)
    return key_bits


@app.route("/")
def index():
    return send_from_directory("static", "video_call.html")


@app.route("/favicon.ico")
def favicon():
    """Avoid 404 in console when browser requests favicon."""
    return Response(b"", status=204)


@app.route("/call/<room_id>")
def call_page(room_id):
    return send_from_directory("static", "video_call.html")


def _clean_expired_secure_files():
    now = time.time()
    expired = [fid for fid, v in secure_files.items() if v["expiry"] < now]
    for fid in expired:
        secure_files.pop(fid, None)


@app.route("/secure-upload", methods=["POST"])
def secure_upload():
    """Accept file + room_id; compress, encrypt with room key, store; return fileId, expiryTime, checksum, encryptedToken."""
    _clean_expired_secure_files()
    try:
        data = request.get_json(force=True, silent=True) or {}
        room_id = (data.get("room_id") or request.form.get("room_id") or "").strip()
        file_b64 = data.get("file") or request.form.get("file")
        filename = (data.get("filename") or request.form.get("filename") or "download").strip()[:200]
        if not room_id or not file_b64:
            return {"error": "room_id and file required"}, 400
        r = get_room(room_id)
        if not r or not r.get("key"):
            return {"error": "Room not found or key not established"}, 400
        key = r["key"]
        raw = base64.b64decode(file_b64)
        original_size = len(raw)
        compressed = zlib.compress(raw, level=9)
        encrypted = call_stego.encrypt_with_key(compressed, key)
        checksum = hashlib.sha256(encrypted).hexdigest()
        file_id = str(uuid.uuid4())
        expiry = time.time() + HYBRID_EXPIRY_SEC
        secure_files[file_id] = {"data": encrypted, "expiry": expiry, "checksum": checksum, "filename": filename, "original_size": original_size}
        retrieval = json.dumps({
            "fileId": file_id,
            "checksum": checksum,
            "expiryTime": expiry,
            "filename": filename,
        }).encode("utf-8")
        encrypted_token = call_stego.encrypt_with_key(retrieval, key)
        _log(f"secure_upload room={room_id} file_id={file_id[:8]}... size={original_size} filename={filename}")
        return {
            "fileId": file_id,
            "expiryTime": expiry,
            "checksum": checksum,
            "encryptedToken": base64.b64encode(encrypted_token).decode("ascii"),
        }
    except Exception as e:
        return {"error": str(e)}, 400


@app.route("/secure-download/<file_id>")
def secure_download(file_id):
    """Serve decrypted file for room_id; validate expiry and checksum. Query: room_id."""
    _clean_expired_secure_files()
    room_id = (request.args.get("room_id") or "").strip()
    if not room_id:
        return {"error": "room_id required"}, 400
    r = get_room(room_id)
    if not r or not r.get("key"):
        return {"error": "Room not found or key not established"}, 400
    if file_id not in secure_files:
        return {"error": "File not found or expired"}, 404
    entry = secure_files[file_id]
    if time.time() > entry["expiry"]:
        secure_files.pop(file_id, None)
        return {"error": "File expired"}, 404
    key = r["key"]
    try:
        dec = call_stego.decrypt_with_key(entry["data"], key)
        raw = zlib.decompress(dec)
    except Exception:
        return {"error": "Decryption failed"}, 400
    secure_files.pop(file_id, None)
    filename = entry.get("filename", "download")
    _log(f"secure_download room={room_id} file_id={file_id[:8]}... filename={filename} size={len(raw)}")
    mimetype = _mime_from_filename(filename)
    if mimetype == "application/octet-stream":
        magic_type = _mime_from_magic(raw[:16])
        if magic_type:
            mimetype = magic_type
    if mimetype == "application/octet-stream" and len(raw) >= 12:
        if raw[:4] == b"RIFF" and raw[8:12] == b"WAVE":
            mimetype = "audio/wav"
        elif raw[4:8] == b"ftyp":
            mimetype = "video/mp4"
        elif raw[:3] == b"ID3":
            mimetype = "audio/mpeg"
    resp = Response(raw, mimetype=mimetype)
    resp.headers["Content-Disposition"] = 'attachment; filename="{}"'.format(_safe_filename_for_header(filename))
    return resp


def _mime_from_filename(filename):
    """Return mimetype for inline display (e.g. video plays in browser)."""
    fn = (filename or "").lower()
    if fn.endswith(".mp4") or fn.endswith(".m4v"):
        return "video/mp4"
    if fn.endswith(".webm"):
        return "video/webm"
    if fn.endswith(".ogg") or fn.endswith(".ogv"):
        return "video/ogg"
    if fn.endswith(".mov"):
        return "video/quicktime"
    if fn.endswith(".avi"):
        return "video/x-msvideo"
    if fn.endswith(".jpg") or fn.endswith(".jpeg"):
        return "image/jpeg"
    if fn.endswith(".png"):
        return "image/png"
    if fn.endswith(".gif"):
        return "image/gif"
    if fn.endswith(".wav"):
        return "audio/wav"
    if fn.endswith(".mp3"):
        return "audio/mpeg"
    if fn.endswith(".m4a"):
        return "audio/mp4"
    return "application/octet-stream"


def _mime_from_magic(data):
    """Infer mimetype from file magic bytes when filename is missing or unknown. data: first 16 bytes."""
    if not data or len(data) < 4:
        return None
    # MP4 / MOV: ftyp at offset 4
    if len(data) >= 12 and data[4:8] == b"ftyp":
        return "video/mp4"
    # WebM: 0x1A 0x45 0xDF 0xA3
    if data[:4] == b"\x1a\x45\xdf\xa3":
        return "video/webm"
    # RIFF....WAVE
    if data[:4] == b"RIFF" and len(data) >= 8 and data[8:12] == b"WAVE":
        return "audio/wav"
    # ID3 (MP3)
    if data[:3] == b"ID3":
        return "audio/mpeg"
    # JPEG
    if data[:2] == b"\xff\xd8":
        return "image/jpeg"
    # PNG
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    return None


def _safe_filename_for_header(filename):
    """Return a filename safe for HTTP headers (must be latin-1 encodable)."""
    if not filename or not isinstance(filename, str):
        return "download"
    try:
        filename.encode("latin-1")
        return filename
    except UnicodeEncodeError:
        return "".join(c if ord(c) < 256 else "_" for c in filename) or "download"


def _safe_ascii(msg):
    """Ensure message is safe for HTML and for WSGI (no Unicode that could break header/body encoding)."""
    if msg is None:
        return "Error"
    s = str(msg).strip()
    return "".join(c if ord(c) < 128 else "?" for c in s)[:500] or "Error"


def _error_html(message, status_code=400):
    """Return an HTML error page so the user sees the message when opening the link in a new tab (instead of black video)."""
    safe_msg = _safe_ascii(message)
    html = (
        "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Secure file</title></head>"
        "<body style='font-family:sans-serif;background:#1a1a1a;color:#eee;padding:2rem;text-align:center'>"
        "<h2>Cannot open secure file</h2><p>" + safe_msg + "</p>"
        "<p style='color:#888;font-size:0.9rem'>Open the link from the Hidden Harbor app while still in the same call, and before the file expires (about 10 minutes).</p>"
        "</body></html>"
    )
    body = html.encode("utf-8")
    r = Response(body, mimetype="text/html; charset=utf-8", status=status_code)
    r.headers["Content-Length"] = str(len(body))
    return r


def _parse_range_header(range_header, total):
    """
    Parse a single bytes= range (RFC 7233). Returns (start, end) inclusive, or None if invalid.
    Supports: bytes=0-499, bytes=500-, bytes=-500 (suffix).
    """
    if not range_header or not isinstance(total, int) or total <= 0:
        return None
    raw = range_header.strip()
    if not raw.lower().startswith("bytes="):
        return None
    s = raw[6:].strip()
    if "," in s:
        s = s.split(",")[0].strip()
    part = s.split("-", 1)
    start_s = (part[0] or "").strip()
    end_s = (part[1].strip() if len(part) > 1 else "").strip()
    try:
        if not start_s and end_s:
            suffix = int(end_s)
            if suffix <= 0:
                return None
            start = max(0, total - suffix)
            end = total - 1
        else:
            start = int(start_s) if start_s else 0
            end = int(end_s) if end_s else total - 1
        if start < 0 or start >= total:
            return None
        end = min(max(end, start), total - 1)
        if end < start:
            return None
        return (start, end)
    except (ValueError, TypeError):
        return None


@app.route("/secure-file/<file_id>")
def secure_file(file_id):
    """
    Serve decrypted file for inline playback (e.g. video in browser).
    Validates room_id, file existence, expiry (404 if not found/expired).
    Supports HTTP Range for video streaming: 206 Partial Content with
    Content-Range, Accept-Ranges: bytes, Content-Length, Content-Type.
    """
    try:
        return _secure_file_impl(file_id)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return _error_html("Server error.", 500)


def _add_cors_headers(resp):
    """Add CORS headers so video/audio can load when page origin differs from server (e.g. different port)."""
    origin = request.headers.get("Origin")
    if origin:
        resp.headers["Access-Control-Allow-Origin"] = origin
    else:
        resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Expose-Headers"] = "Content-Length, Content-Range, Accept-Ranges"


def _secure_file_impl(file_id):
    _clean_expired_secure_files()
    try:
        _log("secure_file {} {} range={}".format(request.method, file_id[:8], request.headers.get("Range", "none")))
    except Exception:
        pass

    # OPTIONS preflight for CORS (e.g. cross-origin video request)
    if request.method == "OPTIONS":
        resp = Response(b"", status=204)
        resp.headers["Allow"] = "GET, HEAD, OPTIONS"
        resp.headers["Access-Control-Allow-Methods"] = "GET, HEAD, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Range"
        resp.headers["Access-Control-Max-Age"] = "86400"
        origin = request.headers.get("Origin")
        resp.headers["Access-Control-Allow-Origin"] = origin if origin else "*"
        return resp

    room_id = (request.args.get("room_id") or "").strip()
    if not room_id:
        return _error_html("Room ID is required in the URL.", 400)

    r = get_room(room_id)
    if not r or not r.get("key"):
        return _error_html("Room not found or secure key not established. Stay in the call and try again.", 403)

    if file_id not in secure_files:
        return _error_html("File not found or already expired. Open the link from the same call (links valid ~10 min).", 404)

    entry = secure_files[file_id]
    if time.time() > entry["expiry"]:
        secure_files.pop(file_id, None)
        return _error_html("This secure file has expired.", 404)

    encrypted_blob = entry.get("data")
    if not encrypted_blob:
        return _error_html("File content is missing.", 404)

    # Cache decrypted bytes so multiple Range requests (video element sends several) don't each pay decrypt cost; avoids timeouts/cancels
    decrypted_bytes = entry.get("decrypted")
    if decrypted_bytes is None:
        try:
            decrypted_compressed = call_stego.decrypt_with_key(encrypted_blob, r["key"])
            decrypted_bytes = zlib.decompress(decrypted_compressed)
        except Exception:
            return _error_html("Decryption failed. The call session may have changed.", 400)
        if not isinstance(decrypted_bytes, bytes):
            decrypted_bytes = bytes(decrypted_bytes) if decrypted_bytes else b""
        if not decrypted_bytes:
            return _error_html("File content is empty after decryption.", 404)
        expected_size = entry.get("original_size")
        if expected_size is not None and len(decrypted_bytes) != expected_size:
            return _error_html("File integrity check failed (size mismatch).", 400)
        entry["decrypted"] = decrypted_bytes

    total = len(decrypted_bytes)
    filename = entry.get("filename", "download")
    mimetype = _mime_from_filename(filename)
    if mimetype == "application/octet-stream":
        magic_type = _mime_from_magic(decrypted_bytes[:16])
        if magic_type:
            mimetype = magic_type
    safe_fn = _safe_filename_for_header(filename)

    range_header = request.headers.get("Range")
    range_spec = _parse_range_header(range_header, total) if range_header else None

    # Range requested but invalid (e.g. start >= total) -> 416 so client doesn't get wrong response and abort (status 0)
    if range_header and range_spec is None:
        resp = Response(b"", status=416)
        resp.headers["Content-Range"] = "bytes */{}".format(total)
        resp.headers["Accept-Ranges"] = "bytes"
        resp.headers["Content-Type"] = mimetype
        _add_cors_headers(resp)
        return resp

    if range_spec is not None:
        start, end = range_spec
        body_slice = decrypted_bytes[start : end + 1]
        body_len = len(body_slice)
        resp = Response(body_slice, mimetype=mimetype, status=206)
        resp.headers["Content-Range"] = "bytes {}-{}/{}".format(start, end, total)
        resp.headers["Accept-Ranges"] = "bytes"
        resp.headers["Content-Length"] = str(body_len)
        resp.headers["Content-Type"] = mimetype
        resp.headers["Content-Disposition"] = 'inline; filename="{}"'.format(safe_fn)
        resp.headers["Cache-Control"] = "no-cache"
        _add_cors_headers(resp)
        return resp

    # No Range header: still return 206 with full range so Chrome's media stack always sees 206 (avoids mixed 200+206 and black 0:00)
    resp = Response(decrypted_bytes, mimetype=mimetype, status=206)
    resp.headers["Content-Range"] = "bytes 0-{}/{}".format(total - 1, total)
    resp.headers["Accept-Ranges"] = "bytes"
    resp.headers["Content-Length"] = str(total)
    resp.headers["Content-Type"] = mimetype
    resp.headers["Content-Disposition"] = 'inline; filename="{}"'.format(safe_fn)
    resp.headers["Cache-Control"] = "no-cache"
    _add_cors_headers(resp)
    return resp


@socketio.on("create_room")
def on_create_room(data):
    """Create a new call room; return room_id and shareable link."""
    sid = request.sid
    room_id = str(uuid.uuid4())[:8]
    mode = (data or {}).get("embed_mode") or "video"
    ensure_room(room_id)
    rooms[room_id]["modes"][sid] = mode
    join_room(room_id)
    rooms[room_id]["sids"].add(sid)
    link = f"/call/{room_id}"
    _log(f"room_created room={room_id} mode={mode} sid={sid[:8]}...")
    emit("room_created", {"room_id": room_id, "link": link, "embed_mode": mode})
    emit("user_joined", {"count": len(rooms[room_id]["sids"])}, room=room_id)


@socketio.on("join_room")
def on_join_room(data):
    """Join existing room by room_id."""
    sid = request.sid
    room_id = (data or {}).get("room_id", "").strip()
    if not room_id or room_id not in rooms:
        _log(f"join_room FAIL room={room_id or '(empty)'} invalid/expired")
        emit("join_error", {"error": "Invalid or expired room."})
        return
    mode = (data or {}).get("embed_mode") or "video"
    join_room(room_id)
    rooms[room_id]["sids"].add(sid)
    rooms[room_id]["modes"][sid] = mode
    count = len(rooms[room_id]["sids"])
    _log(f"join_room room={room_id} mode={mode} peers={count} sid={sid[:8]}...")
    emit("joined_room", {"room_id": room_id, "embed_mode": mode})
    emit("user_joined", {"count": count}, room=room_id)
    # If two peers, run BB84 and notify both
    if count >= 2:
        key_bits = run_bb84_and_set_key(room_id)
        if key_bits:
            r = get_room(room_id)
            key = r.get("key") if r else None
            key_b64 = base64.b64encode(key).decode("ascii") if key else None
            _log(f"key_established room={room_id} ok")
            emit("key_established", {"status": "ok", "key_b64": key_b64}, room=room_id)
        else:
            _log(f"key_established room={room_id} FAIL QBER too high")
            emit("key_established", {"status": "error", "error": "QBER too high"}, room=room_id)


@socketio.on("leave_room")
def on_leave_room(data):
    sid = request.sid
    room_id = (data or {}).get("room_id")
    if room_id and room_id in rooms:
        rooms[room_id]["sids"].discard(sid)
        rooms[room_id].get("modes", {}).pop(sid, None)
        leave_room(room_id)
        _log(f"leave_room room={room_id} peers={len(rooms[room_id]['sids'])}")
        emit("user_joined", {"count": len(rooms[room_id]["sids"])}, room=room_id)


@socketio.on("webrtc_signal")
def on_webrtc_signal(data):
    """Relay WebRTC signaling (offer/answer/ICE) to other peer(s) in room. No server-side media processing."""
    room_id = (data or {}).get("room_id")
    from_sid = getattr(request, "sid", None)
    if not room_id or not from_sid:
        return
    r = get_room(room_id)
    if not r or from_sid not in r["sids"]:
        return
    payload = {"type": data.get("type"), "sdp": data.get("sdp"), "candidate": data.get("candidate"), "from_sid": from_sid}
    emit("webrtc_signal", payload, room=room_id, skip_sid=from_sid)


# --- 3-Tier adaptive transmission ---
TIER1_LIVE_COVERT_MAX_BYTES = 5 * 1024   # < 5KB  -> live_covert
TIER2_STEGO_MEDIA_MAX_BYTES = 100 * 1024  # < 100KB -> stego_media; >= 100KB -> secure_link
STEGO_AUDIO_SAMPLES_MAX = 48000 * 15     # cap for Tier 1 / legacy
STEGO_AUDIO_TIER2_MIN_SAMPLES = 48000 * 5   # Tier 2: minimum 5 sec cover
STEGO_AUDIO_TIER2_MAX_SAMPLES = 48000 * 10  # Tier 2: use up to 10 sec
RMS_MIN_TIER2 = 0.0008   # minimum RMS for Tier 2 (avoid silent/near-silent cover)


def _transmission_mode(payload_size_bytes: int) -> str:
    if payload_size_bytes < TIER1_LIVE_COVERT_MAX_BYTES:
        return "live_covert"
    if payload_size_bytes < TIER2_STEGO_MEDIA_MAX_BYTES:
        return "stego_media"
    return "secure_link"


@socketio.on("send_stego_media")
def on_send_stego_media(data):
    """
    Embed secret into cover media (BB84 key, compress, AES, stego) and broadcast to room.
    3-Tier: live_covert (<5KB), stego_media (5KB–100KB), secure_link (>=100KB) handled by client upload + token.
    """
    from_sid = getattr(request, "sid", None)
    room_id = (data or {}).get("room_id", "").strip()
    embed_mode = (data or {}).get("embed_mode") or "video"
    if not room_id or not from_sid:
        emit("stego_media_error", {"error": "Missing room"})
        return
    r = get_room(room_id)
    if not r or from_sid not in r["sids"]:
        emit("stego_media_error", {"error": "Not in room"})
        return
    key = r.get("key")
    if not key:
        emit("stego_media_error", {"error": "Secure key not established"})
        return

    secret_data = {
        "secret_message": data.get("secret_message"),
        "secret_payload": data.get("secret_payload"),
        "secret_type": (data.get("secret_type") or "text").lower(),
        "chunk_session_id": data.get("chunk_session_id"),
        "chunk_index": data.get("chunk_index"),
        "total_chunks": data.get("total_chunks"),
        "chunk_file_type": data.get("chunk_file_type", "image"),
    }
    is_audio_continuation = (data or {}).get("continuation") and (data or {}).get("session_id")
    secret_bytes = build_secret_bytes(secret_data, key) if not is_audio_continuation else b""
    if not is_audio_continuation and not secret_bytes:
        emit("stego_media_error", {"error": "Nothing to hide (add message or file)"})
        return

    payload_size = len(secret_bytes) if secret_bytes else 0
    mode_selected = _transmission_mode(payload_size) if payload_size else "live_covert"
    if not is_audio_continuation:
        _log("payload_size={} mode_selected={}".format(payload_size, mode_selected))

    try:
        if embed_mode == "audio":
            cover_audio_b64 = (data or {}).get("cover_audio")
            if not cover_audio_b64:
                emit("stego_media_error", {
                    "error": "Microphone required for audio mode. Allow mic access and try again."
                })
                return
            sample_rate = int((data or {}).get("sample_rate") or 48000)
            _log("[AUDIO DEBUG] Received sample_rate from client: {}".format(sample_rate))
            raw = base64.b64decode(cover_audio_b64)
            raw = raw[: (len(raw) // 2) * 2]
            samples = np.frombuffer(raw, dtype=np.int16).copy()
            n_samples = len(samples)
            _save_received_audio_wav(samples, sample_rate)

            if n_samples < 1024:
                emit("stego_media_error", {"error": "Insufficient audio length. Speak into the mic and try again."})
                return

            has_sig_before, rms_before, db_before = _audio_cover_level(samples.tobytes())
            if rms_before < 1e-6:
                emit("stego_media_error", {"error": "Audio has no signal (digital silence). Check mic."})
                return
            if rms_before < RMS_MIN_TIER2 and mode_selected == "stego_media":
                emit("stego_media_error", {"error": "Low RMS: record louder speech for Stego Media (5–10 s)."})
                return

            if mode_selected == "stego_media":
                if n_samples < STEGO_AUDIO_TIER2_MIN_SAMPLES:
                    emit("stego_media_error", {
                        "error": "Stego Media requires at least 5 seconds of cover audio. Keep recording."
                    })
                    return
                if n_samples > STEGO_AUDIO_TIER2_MAX_SAMPLES:
                    samples = samples[-STEGO_AUDIO_TIER2_MAX_SAMPLES:]
                    n_samples = len(samples)
            else:
                if n_samples > STEGO_AUDIO_SAMPLES_MAX:
                    samples = samples[-STEGO_AUDIO_SAMPLES_MAX:]
                    n_samples = len(samples)

            samples = _adaptive_gain(samples, target_rms=0.05)

            state_key = (room_id, from_sid)
            is_continuation = (data or {}).get("continuation") and (data or {}).get("session_id")
            session_id = (data or {}).get("session_id")

            if is_continuation and session_id:
                state = audio_embed_state.get(state_key)
                if not state or state.get("session_id") != session_id:
                    emit("stego_media_error", {"error": "Invalid or expired continuation session. Send the message again."})
                    return
                buffer_bits = state["buffer"]
                stego_parts = state["stego_parts"]
                chunk_index = state.get("chunk_index", 0)
                existing_or_state = state
            else:
                buffer_bits = call_stego.payload_to_bitstream(secret_bytes, key)
                existing = audio_embed_state.get(state_key)
                if existing and existing.get("buffer"):
                    buffer_bits = existing["buffer"] + buffer_bits
                    stego_parts = list(existing.get("stego_parts", []))
                    chunk_index = existing.get("chunk_index", 0)
                    existing_or_state = existing
                else:
                    stego_parts = []
                    chunk_index = 0
                    existing_or_state = {}
                session_id = session_id or str(uuid.uuid4())[:12]

            # Log RMS; all samples eligible, embed every chunk (no RMS skip)
            calibration_rms = (existing_or_state or {}).get("calibration_rms")
            if calibration_rms is None:
                calibration_rms = rms_before
            threshold = max(0.0003, calibration_rms * 0.2)
            _log("chunk_index={} rms={:.6f} threshold={:.6f} embedding_allowed=True".format(
                chunk_index, rms_before, threshold))

            positions = call_stego._audio_embedding_positions(samples, sample_rate)
            eligible_samples = len(positions)
            capacity_bits = eligible_samples

            if buffer_bits:
                stego_samples, bits_embedded, remainder = call_stego.embed_bits_into_audio(samples, buffer_bits, sample_rate)
            else:
                stego_samples, bits_remaining_first = call_stego.embed_in_audio_chunk(samples, secret_bytes, key, sample_rate)
                bitstream_first = call_stego.payload_to_bitstream(secret_bytes, key)
                bits_embedded = len(bitstream_first) - bits_remaining_first
                remainder = bitstream_first[bits_embedded:] if bits_remaining_first > 0 else ""

            bits_remaining = len(remainder)

            _log("chunk_index={} eligible_samples={} capacity_bits={} bits_embedded_this_chunk={} bits_remaining={} rms_value={:.4f}".format(
                chunk_index, eligible_samples, capacity_bits, bits_embedded, bits_remaining, rms_before))

            if bits_remaining > 0:
                _log("Partial embedding: {} bits embedded, {} remaining".format(bits_embedded, bits_remaining))

            stego_parts.append(stego_samples)
            pcm_bytes = stego_samples.tobytes()
            has_sig_after, rms_after, db_after = _audio_cover_level(pcm_bytes)
            final_rms = np.sqrt(np.mean(stego_samples.astype(np.float64) ** 2)) / 32767.0
            _log("[AUDIO DEBUG] Final RMS: {:.6f}".format(final_rms))

            if STEGO_DEBUG_AUDIO and not remainder:
                _debug_audio_compare(samples, stego_samples, first_n=200)
                _debug_audio_sparse_log(samples, stego_samples)
                _debug_save_wav_and_difference(samples, stego_samples, sample_rate=sample_rate)

            if bits_remaining > 0:
                cal = (existing_or_state or {}).get("calibration_rms")
                audio_embed_state[state_key] = {"buffer": remainder, "stego_parts": stego_parts, "session_id": session_id, "chunk_index": chunk_index + 1, "calibration_rms": cal or rms_before}
                emit("stego_media_partial", {"bits_remaining": bits_remaining, "session_id": session_id}, room=from_sid)
            else:
                if len(stego_parts) > 1:
                    full_pcm = np.concatenate(stego_parts).astype(np.int16)
                    pcm_bytes = full_pcm.tobytes()
                else:
                    pcm_bytes = stego_parts[0].tobytes()
                audio_embed_state.pop(state_key, None)
                stego_b64 = base64.b64encode(pcm_bytes).decode("ascii")
                if mode_selected == "stego_media":
                    project_dir = os.path.dirname(os.path.abspath(__file__))
                    out_dir = os.path.join(project_dir, "Results")
                    os.makedirs(out_dir, exist_ok=True)
                    orig_path = os.path.join(out_dir, "original_cover.wav")
                    stego_path = os.path.join(out_dir, "stego_output.wav")
                    try:
                        with wave.open(orig_path, "wb") as w:
                            w.setnchannels(1)
                            w.setsampwidth(2)
                            w.setframerate(sample_rate)
                            w.writeframes(samples.astype(np.int16).tobytes())
                        with wave.open(stego_path, "wb") as w:
                            w.setnchannels(1)
                            w.setsampwidth(2)
                            w.setframerate(sample_rate)
                            w.writeframes(pcm_bytes)
                        _log("Tier 2 WAVs saved: {} , {}".format(orig_path, stego_path))
                    except Exception as e:
                        _log("Tier 2 WAV save failed: {}".format(e))
                _log("send_stego_media room={} type=audio mode={} payload_len={} dB={:.1f}".format(room_id, mode_selected, len(stego_b64), db_after))
                emit("stego_media", {
                    "media_type": "audio",
                    "payload": stego_b64,
                    "sample_rate": sample_rate,
                    "from_sid": from_sid,
                    "has_secret": True,
                    "transmission_mode": mode_selected,
                }, room=room_id)
        elif embed_mode == "video":
            # Video steganography: cover is recorded video (list of frames from client)
            # Cap frames to avoid huge payloads that can disconnect the socket
            MAX_VIDEO_COVER_FRAMES = 8
            cover_frames_b64 = (data or {}).get("cover_frames")
            if not cover_frames_b64 or not isinstance(cover_frames_b64, list) or len(cover_frames_b64) < 1:
                emit("stego_media_error", {"error": "No recorded video (start call and record before sending)"})
                return
            cover_frames_b64 = cover_frames_b64[:MAX_VIDEO_COVER_FRAMES]
            frames = []
            for b64 in cover_frames_b64:
                raw = base64.b64decode(b64)
                arr = np.frombuffer(raw, dtype=np.uint8)
                f = cv2.imdecode(arr, cv2.IMREAD_COLOR)
                if f is None:
                    emit("stego_media_error", {"error": "Invalid frame in recorded video"})
                    return
                frames.append(f)
            cap_bits = call_stego.video_capacity_bits(frames)
            if len(secret_bytes) * 8 > cap_bits:
                emit("stego_media_error", {"error": "Secret too large for recorded video. Record longer or use shorter message/file."})
                return
            stego_frames = call_stego.embed_in_frames(frames, secret_bytes, key)
            stego_frames_b64 = []
            for sf in stego_frames:
                _, buf = cv2.imencode(".png", sf)
                stego_frames_b64.append(base64.b64encode(buf.tobytes()).decode("ascii"))
            out_payload = {
                "media_type": "video_clip",
                "frames": stego_frames_b64,
                "fps": (data or {}).get("fps") or 5,
                "format": "png",
                "from_sid": from_sid,
                "has_secret": True,
            }
            cover_audio_b64 = (data or {}).get("cover_audio")
            if cover_audio_b64:
                out_payload["audio_payload"] = cover_audio_b64
                out_payload["sample_rate"] = (data or {}).get("sample_rate") or 48000
                _log(f"send_stego_media room={room_id} type=video_clip frames={len(stego_frames_b64)} with_audio=yes")
            else:
                _log(f"send_stego_media room={room_id} type=video_clip frames={len(stego_frames_b64)}")
            emit("stego_media", out_payload, room=room_id)
        else:
            # Image snapshot: single frame (image steganography). Only the stego (cover) is broadcast; decryption is on-demand when recipient clicks.
            cover_b64 = (data or {}).get("cover_b64")
            if not cover_b64:
                emit("stego_media_error", {"error": "No cover frame (camera required for image mode)"})
                return
            raw = base64.b64decode(cover_b64)
            arr = np.frombuffer(raw, dtype=np.uint8)
            frame = cv2.imdecode(arr, cv2.IMREAD_COLOR)
            if frame is None:
                emit("stego_media_error", {"error": "Invalid cover image"})
                return
            cap_bits = call_stego.frame_capacity_bits(frame)
            if len(secret_bytes) * 8 > cap_bits:
                emit("stego_media_error", {"error": "Secret too large for this frame. Use a larger image or shorter message."})
                return
            stego_frame = call_stego.embed_in_frame(frame, secret_bytes, key)
            _, buf = cv2.imencode(".png", stego_frame)
            stego_b64 = base64.b64encode(buf.tobytes()).decode("ascii")
            _log(f"send_stego_media room={room_id} type=image payload_len={len(stego_b64)}")
            emit("stego_media", {
                "media_type": "image",
                "payload": stego_b64,
                "format": "png",
                "from_sid": from_sid,
                "has_secret": True,
            }, room=room_id)
    except ValueError as e:
        emit("stego_media_error", {"error": str(e)})
    except Exception as e:
        import traceback
        traceback.print_exc()
        emit("stego_media_error", {"error": "Embed failed: " + str(e)})


@socketio.on("extract")
def on_extract(data):
    """Extract hidden message from media. type: video|audio|image|video_clip. For video_clip pass frames: [b64, ...]."""
    room_id = (data or {}).get("room_id")
    media_type = (data or {}).get("type", "video")
    payload_b64 = data.get("payload")
    frames_b64 = data.get("frames")
    request_id = (data or {}).get("request_id")
    plen = len(payload_b64) if isinstance(payload_b64, str) else 0
    fcount = len(frames_b64) if isinstance(frames_b64, list) else 0
    _log(f"extract room={room_id} type={media_type} request_id={request_id} payload_len={plen} frames={fcount}")
    out = {"success": False, "error": "Missing room or payload", "request_id": request_id}
    if not room_id or (not payload_b64 and not frames_b64):
        emit("extract_result", out)
        return
    r = get_room(room_id)
    key = r.get("key") if r else None
    if not key:
        out["error"] = "No shared key established"
        emit("extract_result", out)
        return
    try:
        blob = None
        if media_type == "video_clip" and frames_b64 and isinstance(frames_b64, list):
            frames = []
            for b64 in frames_b64:
                raw = base64.b64decode(b64)
                arr = np.frombuffer(raw, dtype=np.uint8)
                f = cv2.imdecode(arr, cv2.IMREAD_COLOR)
                if f is None:
                    emit("extract_result", {"success": False, "error": "Invalid frame in video", "request_id": request_id})
                    return
                frames.append(f)
            blob = call_stego.extract_from_frames(frames, key)
        elif media_type == "audio":
            raw = base64.b64decode(payload_b64)
            raw = raw[: (len(raw) // 2) * 2]
            if len(raw) < 64:
                emit("extract_result", {"success": False, "error": "Audio too short.", "request_id": request_id})
                return
            has_sig, rms, db = _audio_cover_level(raw)
            _log(f"extract audio request_id={request_id} audible={has_sig} dB={db:.1f} rms={rms:.6f}")
            samples = np.frombuffer(raw, dtype=np.int16).copy()
            sample_rate = int((data or {}).get("sample_rate") or 48000)
            blob = call_stego.extract_from_audio_chunk(samples, key, sample_rate)
        else:
            raw = base64.b64decode(payload_b64)
            arr = np.frombuffer(raw, dtype=np.uint8)
            frame = cv2.imdecode(arr, cv2.IMREAD_COLOR)
            if frame is None:
                emit("extract_result", {"success": False, "error": "Invalid image data", "request_id": request_id})
                return
            try:
                blob = call_stego.extract_from_frame(frame, key)
            except ValueError as e:
                if "Frame truncated" in str(e) and len(raw) >= 1000 and (len(raw) % 2) == 0:
                    try:
                        samples = np.frombuffer(raw, dtype=np.int16).copy()
                        if len(samples) >= 32:
                            blob = call_stego.extract_from_audio_chunk(samples, key, 48000)
                    except Exception:
                        raise e
                if blob is None:
                    raise e
        if blob is None:
            emit("extract_result", {"success": False, "error": "Could not extract", "request_id": request_id})
            return
        msg, secret_type, secret_payload, chunk_info, hybrid_info = parse_extracted(blob, key)
        out = {"success": True, "request_id": request_id}
        if msg is not None:
            out["message"] = msg
        if secret_type:
            out["secret_type"] = secret_type
        if secret_payload is not None:
            out["secret_payload"] = secret_payload
        if chunk_info:
            out["chunk_session_id"] = chunk_info.get("chunk_session_id")
            out["chunk_index"] = chunk_info.get("chunk_index")
            out["total_chunks"] = chunk_info.get("total_chunks")
            out["chunk_file_type"] = chunk_info.get("file_type")
        if hybrid_info:
            out["file_id"] = hybrid_info.get("file_id")
            out["checksum"] = hybrid_info.get("checksum")
            out["expiry_time"] = hybrid_info.get("expiry_time")
            out["filename"] = hybrid_info.get("filename", "download")
        if not out.get("message") and not out.get("secret_payload") and not hybrid_info:
            out["success"] = False
            out["error"] = "Could not parse extracted content"
        _log(f"extract_result request_id={request_id} success={out.get('success')}")
        emit("extract_result", out)
    except Exception as e:
        import traceback
        _log(f"extract_result request_id={request_id} error={e}")
        traceback.print_exc()
        emit("extract_result", {"success": False, "error": str(e), "request_id": request_id})


@socketio.on("connect")
def on_connect():
    _log(f"connect sid={request.sid[:8]}...")
    emit("connected", {"sid": request.sid})


@socketio.on("disconnect")
def on_disconnect():
    """Remove this socket from every room it was in so peer count stays correct (avoids ghost sids after reconnect/drop)."""
    sid = getattr(request, "sid", None)
    if not sid:
        return
    _log(f"disconnect sid={sid[:8]}...")
    for room_id, r in list(rooms.items()):
        if sid in r.get("sids", set()):
            r["sids"].discard(sid)
            r.get("modes", {}).pop(sid, None)
            leave_room(room_id)
            count = len(r["sids"])
            emit("user_joined", {"count": count}, room=room_id)


if __name__ == "__main__":
    print("🔐 Secure Steganography Video Call — open http://127.0.0.1:5001")
    # use_reloader=False avoids subprocess WebSocket handling issues with Werkzeug
    socketio.run(app, host="0.0.0.0", port=5001, debug=True, use_reloader=False, allow_unsafe_werkzeug=True)
