import cv2
import pywt
import matplotlib.pyplot as plt

img = cv2.imread('image.png', 0)

# 1-level Haar DWT
coeffs = pywt.dwt2(img, 'haar')
LL, (LH, HL, HH) = coeffs

plt.figure(figsize=(10,6))

plt.subplot(2,2,1)
plt.title("LL")
plt.imshow(LL, cmap='gray')
plt.axis('off')

plt.subplot(2,2,2)
plt.title("LH")
plt.imshow(LH, cmap='gray')
plt.axis('off')

plt.subplot(2,2,3)
plt.title("HL")
plt.imshow(HL, cmap='gray')
plt.axis('off')

plt.subplot(2,2,4)
plt.title("HH")
plt.imshow(HH, cmap='gray')
plt.axis('off')

plt.tight_layout()
plt.show()
