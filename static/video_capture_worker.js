/**
 * Web Worker: encodes video frame (ImageData) to JPEG off the main thread.
 * Target ~500kbps equivalent: quality 0.55, called at ~4 fps => ~125KB/frame.
 */
self.onmessage = function (e) {
  var d = e.data;
  if (!d || !d.width || !d.height || !d.data) return;
  var width = d.width;
  var height = d.height;
  var data = d.data;
  try {
    var canvas = new OffscreenCanvas(width, height);
    var ctx = canvas.getContext('2d');
    if (!ctx) {
      self.postMessage({ err: 'no 2d context' });
      return;
    }
    var imageData = new ImageData(new Uint8ClampedArray(data), width, height);
    ctx.putImageData(imageData, 0, 0);
    canvas.convertToBlob({ type: 'image/jpeg', quality: 0.55 })
      .then(function (blob) {
        blob.arrayBuffer().then(function (arrayBuffer) {
          var u8 = new Uint8Array(arrayBuffer);
          var bin = '';
          var chunk = 8192;
          for (var i = 0; i < u8.length; i += chunk) {
            bin += String.fromCharCode.apply(null, u8.subarray(i, i + chunk));
          }
          self.postMessage({ base64: btoa(bin) });
        });
      })
      .catch(function (err) {
        self.postMessage({ err: String(err && err.message) });
      });
  } catch (err) {
    self.postMessage({ err: String(err && err.message) });
  }
};
