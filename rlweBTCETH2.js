const bigInt = require("big-integer");
const secp256k1 = require("secp256k1");
const keccak256 = require("js-sha3").keccak256;
const crypto = require("crypto");
const bitcoin = require("bitcoinjs-lib");

// RLWE Constants
const n = 1024; // Ring dimension (must be a power of 2)
const q = 40961; // Prime modulus
const W = [...Array(n).keys()].map((i) => (i + 1) % q); // Precomputed twiddle factors
const W_rev = [...Array(n).keys()].map((i) => (q - i - 1) % q); // Reverse twiddle factors

// Modular Arithmetic Helpers
function mod(x, m) {
  return bigInt(x).mod(m).toJSNumber();
}

function mulMod(a, b, m) {
  return bigInt(a).multiply(b).mod(m).toJSNumber();
}

function addMod(a, b, m) {
  return bigInt(a).add(b).mod(m).toJSNumber();
}

function subMod(a, b, m) {
  return bigInt(a).subtract(b).mod(m).toJSNumber();
}

// FFT Functions
function fftForward(x) {
  let step = 1;
  for (let m = n >> 1; m >= 1; m >>= 1) {
    let index = 0;
    for (let j = 0; j < m; j++) {
      for (let i = j; i < n; i += m << 1) {
        const t0 = addMod(x[i], x[i + m], q);
        const t1 = mulMod(subMod(x[i], x[i + m], q), W[index], q);
        x[i] = t0;
        x[i + m] = t1;
      }
      index = mod(index + (n - step), n);
    }
    step <<= 1;
  }
}

function fftBackward(x) {
  let step = n >> 1;
  for (let m = 1; m < n; m <<= 1) {
    let index = 0;
    for (let j = 0; j < m; j++) {
      for (let i = j; i < n; i += m << 1) {
        const t0 = x[i];
        const t1 = mulMod(x[i + m], W_rev[index], q);
        x[i] = addMod(t0, t1, q);
        x[i + m] = subMod(t0, t1, q);
      }
      index = mod(index + (n - step), n);
    }
    step >>= 1;
  }
}

// RLWE Key Exchange Functions
function generateKeyPair() {
  const privateKey = Array.from({ length: n }, () => Math.floor(Math.random() * q));
  const publicKey = privateKey.slice();
  fftForward(publicKey);
  return { privateKey, publicKey };
}

function encapsulate(publicKey) {
  const randomPoly = Array.from({ length: n }, () => Math.floor(Math.random() * q));
  const ciphertext = randomPoly.slice();
  fftForward(ciphertext);
  const sharedSecret = randomPoly.map((val, i) => mulMod(val, publicKey[i], q));
  return { ciphertext, sharedSecret };
}

function decapsulate(ciphertext, privateKey) {
  const sharedSecret = ciphertext.map((val, i) => mulMod(val, privateKey[i], q));
  fftBackward(sharedSecret);
  return sharedSecret;
}

// BTC and ETH Key Pair Generation
function sharedSecretToEntropy(sharedSecret) {
  const hash = crypto.createHash("sha256");
  sharedSecret.forEach((val) => hash.update(Buffer.from(val.toString())));
  return hash.digest(); // 32 bytes of entropy
}

function generateBTCKeyPair(sharedSecret) {
  const entropy = sharedSecretToEntropy(sharedSecret);
  const privateKey = Buffer.from(entropy);
  const publicKey = secp256k1.publicKeyCreate(privateKey);
  return { privateKey: privateKey.toString("hex"), publicKey: publicKey.toString("hex") };
}

function generateETHKeyPair(sharedSecret) {
  const entropy = sharedSecretToEntropy(sharedSecret);
  const privateKey = Buffer.from(entropy);
  const publicKey = secp256k1.publicKeyCreate(privateKey, false).slice(1); // Remove prefix byte
  const address = keccak256(publicKey).slice(-40); // Last 20 bytes of Keccak-256 hash
  return { privateKey: privateKey.toString("hex"), address: `0x${address}` };
}

// Main Execution
try {
  // RLWE Key Exchange
  const { privateKey, publicKey } = generateKeyPair();
  const { ciphertext, sharedSecret: senderSharedSecret } = encapsulate(publicKey);
  const receiverSharedSecret = decapsulate(ciphertext, privateKey);

  // Generate BTC and ETH Keys
  const btcKeys = generateBTCKeyPair(receiverSharedSecret);
  console.log("BTC Private Key:", btcKeys.privateKey);
  console.log("BTC Public Key:", btcKeys.publicKey);

  const ethKeys = generateETHKeyPair(receiverSharedSecret);
  console.log("ETH Private Key:", ethKeys.privateKey);
  console.log("ETH Address:", ethKeys.address);
} catch (error) {
  console.error("Error:", error.message);
}