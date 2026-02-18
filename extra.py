import cv2
import numpy as np
from matplotlib import pyplot as plt

# ============================
# 1️⃣ Read Grayscale Image
# ============================
img = cv2.imread('Ak1.png', cv2.IMREAD_GRAYSCALE)

# ============================
# 2️⃣ Global Histogram Equalization (GHE)
# ============================
def global_hist_eq(image):
    hist, bins = np.histogram(image.flatten(), 256, [0, 256])
    cdf = hist.cumsum()                           # cumulative distribution
    cdf_normalized = cdf * 255 / cdf[-1]          # normalize to [0,255]
    equalized = np.interp(image.flatten(), bins[:-1], cdf_normalized)
    return equalized.reshape(image.shape).astype(np.uint8)

ghe = global_hist_eq(img)

# ============================
# 3️⃣ 3x3 Median Filter
# ============================
median_filtered = cv2.medianBlur(img, 3)

# ============================
# 4️⃣ 5x5 Max and Min Filters
# ============================
kernel = np.ones((5,5), np.uint8)
max_filtered = cv2.dilate(img, kernel)   # Max filter = dilation
min_filtered = cv2.erode(img, kernel)    # Min filter = erosion

# ============================
# 5️⃣ Morphological Gradient
# ============================
morph_gradient = cv2.subtract(max_filtered, min_filtered)

# ============================
# 6️⃣ Display Results
# ============================
titles = ['Original', 'GHE', 'Median (3x3)', 'Max (5x5)', 'Min (5x5)', 'Morph Gradient']
images = [img, ghe, median_filtered, max_filtered, min_filtered, morph_gradient]

for i in range(6):
    plt.subplot(2, 3, i+1)
    plt.imshow(images[i], cmap='gray')
    plt.title(titles[i])
    plt.axis('off')

plt.tight_layout()
plt.show()
