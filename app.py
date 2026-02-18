import os
import cv2
import numpy as np
from flask import Flask, request, jsonify, send_file, send_from_directory
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from groq import Groq
from TextStegano import txt_decode, txt_encode
from ImageStegano import encode_image_file, decode_image_file
from AudioStegno import encode_aud_data, decode_aud_data
from imageStegHelper import ImageSteg

# =========================================================
# Flask setup
# =========================================================
app = Flask(__name__, static_folder="static", template_folder="static")
UPLOAD_DIR = "uploads"
RESULT_DIR = "Result_files"
SAMPLE_COVERS = "Sample_cover_files"
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(RESULT_DIR, exist_ok=True)

# =========================================================
# Load environment variables
# =========================================================
load_dotenv()
api_key = os.getenv("GROQ_API_KEY")
client = None
if api_key:
    client = Groq(api_key=api_key)
    print("✅ Groq API loaded successfully!")
else:
    print("⚠️  GROQ_API_KEY not found. Using fallback replies.")

# =========================================================
# AI reply function — GROQ (Llama 3)
# =========================================================
def ai_reply(prompt: str) -> str:
    """Generate AI reply using Groq API"""
    if not client:
        return f"Bot reply to: '{prompt}' (no API key)"

    try:
        completion = client.chat.completions.create(
            model="llama3-8b-8192",
            messages=[
                {"role": "system",
                 "content": "You are StegaBot, a friendly AI assistant who replies concisely and politely to hidden messages."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=150
        )
        return completion.choices[0].message.content.strip()
    except Exception as e:
        print(f"❌ Groq API error: {e}")
        return f"(AI error) Bot reply to: '{prompt}'"

# =========================================================
# Video steganography helpers
# =========================================================
def encode_video_file(video_path, message, output_folder=RESULT_DIR):
    steg = ImageSteg()
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        raise FileNotFoundError("Cannot open video file.")

    fps = cap.get(cv2.CAP_PROP_FPS)
    w = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    h = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    fourcc = cv2.VideoWriter_fourcc(*"mp4v")

    out_path = os.path.join(output_folder,
                            os.path.splitext(os.path.basename(video_path))[0] + "_embedded.mp4")
    writer = cv2.VideoWriter(out_path, fourcc, fps, (w, h))

    success, frame = cap.read()
    i = 0
    while success:
        if i == 0:
            tmp = os.path.join(output_folder, "tmp_frame.png")
            from PIL import Image
            Image.fromarray(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)).save(tmp)
            embedded = steg.encrypt_text_in_image(tmp, message, output_folder)
            img = cv2.imread(embedded)
            writer.write(img)
            os.remove(tmp)
        else:
            writer.write(frame)
        success, frame = cap.read()
        i += 1

    cap.release()
    writer.release()
    return out_path


def decode_video_file(video_path):
    steg = ImageSteg()
    cap = cv2.VideoCapture(video_path)
    success, frame = cap.read()
    cap.release()
    if not success:
        raise ValueError("Could not read first frame of video.")

    tmp = os.path.join(RESULT_DIR, "tmp_frame.png")
    from PIL import Image
    Image.fromarray(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)).save(tmp)
    decoded = steg.decrypt_text_in_image(tmp)
    os.remove(tmp)
    return decoded

# =========================================================
# Routes
# =========================================================
@app.route("/")
def home():
    return send_from_directory("static", "ui.html")

@app.route("/upload-and-decode", methods=["POST"])
def upload_and_decode():
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No file uploaded"}), 400

    f = request.files["file"]
    filename = secure_filename(f.filename)
    save_path = os.path.join(UPLOAD_DIR, filename)
    f.save(save_path)

    mode = request.form.get("mode", "").lower()
    if not mode:
        ext = os.path.splitext(filename)[1].lower()
        mode = {
            ".txt": "text",
            ".png": "image", ".jpg": "image", ".jpeg": "image",
            ".wav": "audio",
            ".mp4": "video", ".mov": "video", ".mkv": "video",
        }.get(ext, "text")

    # ---------- Decode ----------
    try:
        if mode == "text":
            decoded = txt_decode(save_path)
        elif mode == "image":
            decoded = decode_image_file(save_path)
        elif mode == "audio":
            decoded = decode_aud_data(save_path)
        elif mode == "video":
            decoded = decode_video_file(save_path)
        else:
            raise ValueError("Unsupported mode.")
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

    # ---------- AI reply ----------
    bot_text = ai_reply(decoded)
    reply_path = None

    # ---------- Optional re-encode ----------
    if request.form.get("re_encrypt", "false").lower() == "true":
        try:
            if mode == "text":
                cover = os.path.join(SAMPLE_COVERS, "SampleText.txt")
                reply_path = txt_encode(bot_text, cover)
            elif mode == "image":
                reply_path = encode_image_file("SampleImage.png", bot_text)
            elif mode == "audio":
                reply_path = encode_aud_data("SampleAudio.wav", bot_text, RESULT_DIR)
            elif mode == "video":
                reply_path = encode_video_file("SampleVideo.mp4", bot_text)
        except Exception as e:
            print("Re-encode failed:", e)

    return jsonify({
        "success": True,
        "decoded_message": decoded,
        "bot_reply": bot_text,
        "reply_stego_path": reply_path
    })

@app.route("/download")
def download():
    path = request.args.get("path")
    if not path or not os.path.exists(path):
        return jsonify({"error": "File not found"}), 404
    return send_file(path, as_attachment=True)

# =========================================================
# Main
# =========================================================
if __name__ == "__main__":
    app.run(debug=True, port=5000)
