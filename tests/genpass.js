import Assert from "node:assert/strict";
import GenPass from "genpass";

let BaseX = {};

/**
 * @param {Array<String>|String} ALPHABET
 * @param {String} string
 */
BaseX.decode = function (ALPHABET, string) {
  let BASE = ALPHABET.length;
  let buffer = BaseX._decodeUnsafe(ALPHABET, string);
  if (buffer) {
    return buffer;
  }
  throw new Error("Non-base" + BASE + " character");
};

/**
 * @param {Array<String>|String} ALPHABET
 * @param {String} source
 */
BaseX._decodeUnsafe = function (ALPHABET, source) {
  /* jshint bitwise: false */

  let BASE_MAP = new Uint8Array(256);
  for (let j = 0; j < BASE_MAP.length; j += 1) {
    BASE_MAP[j] = 255;
  }
  for (let i = 0; i < ALPHABET.length; i += 1) {
    let x = ALPHABET[i];
    let xc = x.charCodeAt(0);
    let blank = BASE_MAP[xc] === 255;
    if (!blank) {
      throw new TypeError(`'${x}' (${xc}) is ambiguous`);
    }
    BASE_MAP[xc] = i;
  }

  let BASE = ALPHABET.length;
  let LEADER = ALPHABET[0].charAt(0);
  let FACTOR = Math.log(BASE) / Math.log(256); // log(BASE) / log(256), rounded up

  if (typeof source !== "string") {
    throw new TypeError("Expected String");
  }
  if (source.length === 0) {
    return new Uint8Array(0);
  }
  let psz = 0;
  // Skip and count leading '1's.
  let zeroes = 0;
  let length = 0;
  while (source[psz] === LEADER) {
    zeroes += 1;
    psz += 1;
  }
  // Allocate enough space in big-endian base256 representation.
  let size = ((source.length - psz) * FACTOR + 1) >>> 0; // log(58) / log(256), rounded up.
  let b256 = new Uint8Array(size);
  // Process the characters.
  while (source[psz]) {
    // Decode character
    let carry = BASE_MAP[source.charCodeAt(psz)];
    // Invalid character
    if (carry === 255) {
      return null;
    }
    let i = 0;
    for (
      let it3 = size - 1;
      (carry !== 0 || i < length) && it3 !== -1;
      it3 -= 1, i += 1
    ) {
      carry += (BASE * b256[it3]) >>> 0;
      b256[it3] = carry % 256 >>> 0;
      carry = (carry / 256) >>> 0;
    }
    if (carry !== 0) {
      throw new Error("Non-zero carry");
    }
    length = i;
    psz += 1;
  }
  // Skip leading zeroes in b256.
  let it4 = size - length;
  while (it4 !== size && b256[it4] === 0) {
    it4 += 1;
  }
  let vch = new Uint8Array(zeroes + (size - it4));
  let j = zeroes;
  while (it4 !== size) {
    vch[j] = b256[it4];
    j += 1;
    it4 += 1;
  }
  return vch;
};

let base = GenPass.bases.base62 + GenPass.specials;
let charset = GenPass.calculateAllowed(base, GenPass.blacklist);
console.info(`charset = `, charset);
console.info(`base = ${charset.length}`);

for (let count = 0; count < 1000; count += 1) {
  for (let i = 1; i <= 40; i += 1) {
    let numChars = i;
    let numBits = GenPass.getMinBits(charset.length, numChars);
    // console.info(`${numChars} chars = ${numBits} bits`, numBits);

    let numBytes = GenPass.bitsToBytes(numBits);
    let rndBytes = new Uint8Array(numBytes);
    crypto.getRandomValues(rndBytes);

    // console.log(rndBytes);
    let rnd = GenPass.baseXencode(charset, rndBytes);
    // console.info(`rnd ${rnd}`);

    let decBytes = BaseX.decode(charset, rnd);
    // console.info(`decBytes`, decBytes);

    let rndArr = Array.from(rndBytes);
    let decArr = Array.from(decBytes);
    Assert.deepEqual(rndArr, decArr, "bad encoding");
  }
}
console.info(`PASS: (sanity check) proper baseX conversion`);

let numBitsHigh = GenPass.getMinBits(charset.length, 14);
{
  let rnd = GenPass.generateChars(charset, 14);
  Assert.equal(rnd.length, 14);
  console.info(
    `PASS: generate ${rnd.length}-char password: ${rnd} (${numBitsHigh}-bit)`,
  );
}

{
  let alphanumRe = /^[a-z0-9]+$/i;
  for (let count = 0; count < 1000; count += 1) {
    let rnd = GenPass.generateChars(charset, 14);
    let hasSpecial = !alphanumRe.test(rnd);
    Assert.ok(hasSpecial, `${count}: missing special characters ${rnd}`);
  }
  console.info(`PASS: force special characters when included`);
}

{
  let alphanumRe = /^[a-z0-9]+$/i;
  let plain = false;
  for (let count = 0; count < 1000; count += 1) {
    let rnd = GenPass.generateChars(charset, 4);
    plain = alphanumRe.test(rnd);
    if (plain) {
      break;
    }
  }
  Assert.ok(plain, `forced special characters even for short passwords`);
  console.info(`PASS: don't force special characters for short passwords`);
}

{
  void GenPass.generateChars("abc123", 14);
  // infinite loop otherwise
  console.info(`PASS: don't force special characters when not included`);
}

let numBitsLow = GenPass.getMinBits(charset.length, 13);
numBitsLow += 1;
{
  let rndLow = GenPass.generateBits(charset, numBitsLow);
  let numChars = GenPass.getMinChars(charset.length, numBitsLow);
  Assert.equal(rndLow.length, numChars);
  console.info(
    `PASS: generate ${numBitsLow}-bit password: ${rndLow} (${rndLow.length}-chars)`,
  );
}

{
  let rndHigh = GenPass.generateBits(charset, numBitsHigh);
  let numChars = GenPass.getMinChars(charset.length, numBitsHigh);
  Assert.equal(rndHigh.length, numChars);
  console.info(
    `PASS: generate ${numBitsHigh}-bit password: ${rndHigh} (${rndHigh.length}-chars)`,
  );
}
