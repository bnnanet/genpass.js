let GenPass = {};

GenPass.bases = {
  base64: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", // RFC-order
  base64_url:
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
  base62: "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", // ASCII order
  base58: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
  base32_crockford: "0123456789abcdefghjkmnpqrstvwxyz",
  hex: "0123456789abcdef",
  octal: "012345678",
  binary: "01",
};

GenPass.specials = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

/**
 * Characters that can begin or end a quoted or special sequence,
 * or that may otherwise expose flaws in a poorly escaped system.
 */
GenPass.blacklists = {
  basic_auth: ":",
  html: "\"&'<>`",
  // Note:
  // Chromium only escapes ' "<>`'
  // encodeURIComponent() only allows "!'()*-._~"
  // We consider both GET https://user:pass@example.com/
  //             and POST https://example.com/?pass=pass
  url: ' "#%&+/:<>?@`',
  shell: "\"$'\\`", // () is only special when unquoted
  sql: "\"';",
  postgresql: "'",
  mysql: `"%'\\`,
  mssql: `"';[\\]`,
  smb: '"*:<>?|',
};

let _blacklists = Object.values(GenPass.blacklists);
GenPass.blacklist = _blacklists.join("");

/**
 * Calculates the character set to use for the password.
 *
 * @param {String} charset
 * @param {String} blacklist
 * @returns {String} - the allowed character set
 */
GenPass.calculateAllowed = function (charset, blacklist) {
  let charsetArr = charset.split("");
  let blacklistArr = blacklist.split("");

  let charsArr = [];
  for (let c of charsetArr) {
    let inBlacklist = blacklistArr.indexOf(c) >= 0;
    if (!inBlacklist) {
      charsArr.push(c);
    }
  }

  let newCharset = charsArr.join("");
  return newCharset;
};

/**
 * Generates n+1 (for padding) cryptographically random bytes
 *
 * @param {Number} [n=64]
 * @returns {Uint8Array}
 */
GenPass.generateBytes = function (n = 64) {
  n += 1; // 1 extra for padding

  let rand65 = new Uint8Array(n);
  crypto.getRandomValues(rand65);

  return rand65;
};

// TODO bring generateChars and generateBits back

/**
 * Generate password with a minimum number of characters.
 *
 * @param {String} charset
 * @param {Number} numChars
 * @returns {String}
 */
GenPass.generateChars = function (charset, numChars) {
  let numBits = GenPass.getMinBits(charset.length, numChars + 4);
  let numBytes = GenPass.bitsToBytes(numBits);
  numBytes = Math.max(64, numBytes);
  let rand65 = GenPass.generateBytes(numBytes);

  let rnd = GenPass.encodeChars(charset, rand65, numChars);
  return rnd;
};

/**
 * Generate a password with minimum bit-entropy.
 *
 * @param {String} charset
 * @param {Number} numBits
 */
GenPass.generateBits = function (charset, numBits) {
  let numChars = GenPass.getMinChars(charset.length, numBits);

  let rnd = GenPass.generateChars(charset, numChars);
  return rnd;
};

/**
 * Encode the given bytes as a password of the given length in the given charset.
 *
 * @param {String} charset
 * @param {Uint8Array} rand65 - 65 random bytes (64 + 1 for padding)
 * @param {Number} numChars
 */
GenPass.encodeChars = function (charset, rand65, numChars) {
  if (!numChars) {
    let bitsPerChar = GenPass.logN(charset.length, 2);
    let safeBytes = rand65.length - 1;
    let totalBits = safeBytes * 8;
    let numCharsF = totalBits / bitsPerChar;
    numChars = Math.floor(numCharsF);
  }

  let alphanumRe = /^[a-z0-9]*$/i;
  let needsSpecial = !alphanumRe.test(charset) && numChars >= 6;

  let numBits = GenPass.getMinBits(charset.length, numChars + 4);
  let numBytes = GenPass.bitsToBytes(numBits);
  if (rand65.length <= numBytes) {
    numBytes += 1;
    let msg = `needed ${numBytes} random bytes, but got ${rand65.length}`;
    throw new Error(msg);
  }

  let rndSource = GenPass.baseXencode(charset, rand65);
  let rnd = "";
  // drop leading character, which may be 0-padded
  for (let start = 1; start < 1000; start += 1) {
    rnd = rndSource.slice(start, start + numChars);
    if (rnd.length < numChars) {
      let msg = `no special characters could be encoded from the ${rand65.length} given bytes - they may not be uniformly cryptographically random, or there may be too few`;
      throw new Error(msg);
    }

    if (needsSpecial) {
      let hasSpecial = !alphanumRe.test(rnd);
      if (!hasSpecial) {
        continue;
      }
    }
    break;
  }

  return rnd;
};

/**
 * Encode the given bytes as a password of the given length in the given charset.
 *
 * @param {String} charset
 * @param {Uint8Array} rand65 - 65 random bytes (64 + 1 for padding)
 * @param {Number} numBits
 */
GenPass.encodeBits = function (charset, rand65, numBits) {
  let numChars = GenPass.getMinChars(charset.length, numBits);

  let rnd = GenPass.encodeChars(charset, rand65, numChars);
  return rnd;
};

/**
 * Calculate the minimum bit entropy for the number of characters in a given base
 *
 * @param {Number} base - size of dictionary (ex: 74)
 * @param {Number} numChars - number of characters
 */
GenPass.getMinBits = function (base, numChars) {
  let bitsPerChar = GenPass.logN(base, 2);
  let bitsF = bitsPerChar * numChars;
  let bitsStr = bitsF.toFixed(8);
  bitsF = parseFloat(bitsStr);
  let numBits = Math.floor(bitsF);
  return numBits;
};

/**
 * Calculate the minimum number of characters in the base for the target bit entropy
 *
 * @param {Number} base - size of dictionary (ex: 74)
 * @param {Number} numBits - number of characters
 */
GenPass.getMinChars = function (base, numBits) {
  let bitsPerChar = GenPass.logN(base, 2);
  let charsF = numBits / bitsPerChar;
  let charsStr = charsF.toFixed(8);
  charsF = parseFloat(charsStr);
  let numChars = Math.ceil(charsF);
  return numChars;
};

/**
 * @param {Number} numBits - number of characters
 */
GenPass.bitsToBytes = function (numBits) {
  let numBytes = numBits / 8;
  numBytes = Math.ceil(numBytes);

  return numBytes;
};

// base58 (base-x) encoding
// Copyright (c) 2021-2022 AJ ONeal (base62)
// Copyright (c) 2018 base-x contributors
// Copyright (c) 2014-2018 The Bitcoin Core developers (base58.cpp)
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
//
// Taken from https://github.com/therootcompany/base62.js
// which is a fork of https://github.com/cryptocoinjs/base-x
/**
 * @param {Array<String>|String} ALPHABET
 * @param {Uint8Array} source
 */
GenPass.baseXencode = function (ALPHABET, source) {
  /* jshint bitwise: false */

  let BASE = ALPHABET.length;
  let LEADER = ALPHABET[0].charAt(0);
  let iFACTOR = GenPass.logN(256, BASE); // log(256) / log(BASE), rounded up

  if (source.length === 0) {
    return "";
  }

  // Skip & count leading zeroes.
  let zeroes = 0;
  let length = 0;
  let pbegin = 0;
  let pend = source.length;
  while (pbegin !== pend && source[pbegin] === 0) {
    pbegin += 1;
    zeroes += 1;
  }

  // Allocate enough space in big-endian base58 representation.
  let len = pend - pbegin;
  let num = len * iFACTOR;
  let size = num + 1;
  size = size >>> 0;
  let b58 = new Uint8Array(size);
  // Process the bytes.
  while (pbegin !== pend) {
    let carry = source[pbegin];
    // Apply "b58 = b58 * 256 + ch".
    let i = 0;
    let it1 = size - 1;
    for (;;) {
      let cont = (carry !== 0 || i < length) && it1 !== -1;
      if (!cont) {
        break;
      }

      carry += (256 * b58[it1]) >>> 0;
      b58[it1] = carry % BASE >>> 0;
      carry = (carry / BASE) >>> 0;

      it1 -= 1;
      i += 1;
    }
    if (carry !== 0) {
      throw new Error("Non-zero carry");
    }
    length = i;
    pbegin += 1;
  }
  // Skip leading zeroes in base58 result.
  let it2 = size - length;
  while (it2 !== size && b58[it2] === 0) {
    it2 += 1;
  }
  // Translate the result into a string.
  let str = LEADER.repeat(zeroes);
  for (; it2 < size; it2 += 1) {
    let index = b58[it2];
    str += ALPHABET[index];
  }
  return str;
};

/**
 * @param {Number} n
 * @param {Number} N
 */
GenPass.logN = function (n, N) {
  let log = Math.log(n) / Math.log(N);
  return log;
};

export default GenPass;
