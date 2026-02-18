# Hidden Harbor — Secure Steganography Video Call

Real-time video call that hides secret messages inside audio chunks, video frames, or instant image snapshots using BB84-derived encryption and LSB steganography.

## Quick start

1. **Install dependencies** (if not already):
   ```bash
   pip install -r requirements_video_call.txt
   # or: pip install flask flask-socketio numpy opencv-python-headless pycryptodome
   ```

2. **Run the server** (local):
   ```bash
   python3 video_call_server.py
   ```
   Server runs at **http://127.0.0.1:5001**

3. **Open in browser**:
   - User A: open http://127.0.0.1:5001 → choose embed mode (Audio / Video / Image) → **Start a call**
   - Copy the shareable link and open it in another tab or browser (User B)
   - User B: open the link → choose mode → **Join with link / ID**
   - When both are in the room, **BB84 key exchange** runs automatically; you’ll see “Secure key established”

4. **During the call**:
   - Your webcam and mic stream to the peer.
   - Type a message and click **Send as hidden** — the next frame/chunk/snapshot will carry that message (encrypted and embedded).
   - On the receiver side, click **Extract hidden message from last received** to decrypt and show the hidden text.

## Embed modes

- **Audio chunks**: Hidden data in LSB of raw PCM (int16) chunks.
- **Video frames**: Hidden data in LSB of pixels (with key-based position randomization).
- **Instant image snapshots**: Screenshots of your video used as carrier images; same LSB embedding.

## Files

- `video_call_server.py` — Flask-SocketIO server, rooms, BB84, embed/extract.
- `static/video_call.html` — Single-page UI (modal, video panel, message input, extract).
- `call_stego.py` — In-memory steganography (audio/video/image) and BB84 key crypto.

## Video-in-video steganography (which file does what)

| What | File | Details |
|------|------|--------|
| **Embed secret in recorded video (multi-frame)** | `call_stego.py` | `embed_in_frames()`, `extract_from_frames()`, `video_capacity_bits()` — LSB embedding across frames with key-based shuffle. |
| **Send/receive video stego** | `video_call_server.py` | `on_send_stego_media`: when `embed_mode == "video"`, accepts `cover_frames` (base64 list), decodes with OpenCV, calls `call_stego.embed_in_frames`, emits `stego_media` with `media_type: "video_clip"`. `on_extract`: when `type == "video_clip"`, decodes frames and calls `call_stego.extract_from_frames`. |
| **Record video as cover and send** | `static/video_call.html` | `videoFrameBuffer`, `startVideoRecording()` / `captureFrameSync(true)` (at `VIDEO_RECORD_FPS`), "Send as hidden" builds `cover_frames` and either `uploadAndEmbedLinkInCover` (file) or `socket.emit('send_stego_media', { cover_frames, ... })`. Click-to-decrypt for `video_clip` sends `extract` with `type: 'video_clip'`, `frames`. |

## Security note

BB84 is **simulated** (server runs the protocol and distributes the same key to both peers). For real QKD you’d use a quantum channel; here it demonstrates the flow and key usage for encryption and randomized embedding.
