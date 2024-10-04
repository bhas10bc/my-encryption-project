const CryptoJS = require("crypto-js");

// Function to encrypt data using AES in CBC mode
function encryptData(data) {
  const key = CryptoJS.enc.Utf8.parse("6368616e676520746869732070617373");
  const iv = CryptoJS.lib.WordArray.random(16); // Generate random IV

  // Encrypt the data
  const encrypted = CryptoJS.AES.encrypt(data, key, {
    iv: iv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7,
  });

  // Combine IV and ciphertext into one hex string
  const ivHex = iv.toString(CryptoJS.enc.Hex);
  const ctHex = encrypted.ciphertext.toString(CryptoJS.enc.Hex);

  return ivHex + ctHex; // Return IV + Ciphertext
}

// Example usage
const dataToEncrypt = "Hello, Go!";
const encryptedMessage = encryptData(dataToEncrypt);
console.log("Encrypted Message:", encryptedMessage);
