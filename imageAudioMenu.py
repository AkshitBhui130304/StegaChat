# =======================================================
# imageAudioMenu.py
# =======================================================

from imageAudioStegHelper import ImageAudioSteg

def encode_menu():
    cover = input("Enter cover WAV path (16-bit PCM): ").strip()
    secret_image = input("Enter secret image path (png/jpg/...): ").strip()
    output = input("Enter output stego WAV path (default: stego.wav): ").strip() or "stego.wav"
    password = input("Enter encryption password: ").strip()
    bits = input("Enter bits per sample to use (1-4, default 2): ").strip()
    bits = int(bits) if bits else 2

    steg = ImageAudioSteg()
    try:
        steg.encrypt_image_into_audio(cover, secret_image, output, password, bits_per_sample=bits)
    except Exception as e:
        print(f"❌ Error: {e}")

def decode_menu():
    stego = input("Enter stego WAV path: ").strip()
    out_image = input("Enter output image filename (e.g. recovered.png): ").strip()
    password = input("Enter password: ").strip()
    bits = input("Enter bits per sample used during encoding (1-4, default 2): ").strip()
    bits = int(bits) if bits else 2

    steg = ImageAudioSteg()
    try:
        steg.decrypt_image_from_audio(stego, out_image, password, bits_per_sample=bits)
    except Exception as e:
        print(f"❌ Error: {e}")

def menu():
    print("\n===== IMAGE → AUDIO STEGANOGRAPHY (Huffman + AES) =====")
    print("1️⃣  Encrypt (Hide image inside WAV audio)")
    print("2️⃣  Decrypt (Recover image from WAV)")
    choice = input("\nEnter choice (1/2): ").strip()
    if choice == "1":
        encode_menu()
    elif choice == "2":
        decode_menu()
    else:
        print("❌ Invalid choice.")

if __name__ == "__main__":
    menu()
