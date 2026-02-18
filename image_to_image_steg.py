# =======================================================
# image_stego_menu.py
# =======================================================

import os
from imageStegHelper1 import ImageSteg

def multi_image_encode():
    cover_list = input("Enter cover image paths (comma-separated): ").strip().split(",")
    secret_path = input("Enter secret image path: ").strip()
    output_folder = input("Enter output folder (default: Result_files): ").strip() or "Result_files"
    password = input("Enter password: ").strip()

    steg = ImageSteg()
    print("\n🔹 Encoding secret across multiple cover images...")
    steg.encrypt_image_in_multiple_covers([c.strip() for c in cover_list], secret_path, output_folder, password)

def multi_image_decode():
    stego_list = input("Enter stego image paths (comma-separated): ").strip().split(",")
    output_secret = input("Enter output secret image name (e.g. recovered.png): ").strip()
    password = input("Enter password: ").strip()

    steg = ImageSteg()
    print("\n🔹 Decoding secret from multiple stego images...")
    steg.decrypt_image_from_multiple_covers([s.strip() for s in stego_list], output_secret, password)

def menu():
    print("\n===== MULTI-IMAGE STEGANOGRAPHY (Huffman + AES) =====")
    print("1️⃣  Encrypt (Hide Secret Across Multiple Images)")
    print("2️⃣  Decrypt (Reconstruct Secret Image)")
    choice = input("\nEnter choice (1/2): ").strip()

    if choice == "1":
        multi_image_encode()
    elif choice == "2":
        multi_image_decode()
    else:
        print("❌ Invalid choice.")

if __name__ == "__main__":
    menu()
