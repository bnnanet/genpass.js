import GenPass from "@root/genpass";

let numCharsStr = process.argv[2] || "16";
let numChars = parseInt(numCharsStr, 10);
let entropy = GenPass.generatePaddedBytes();

let alphanums = GenPass.bases.base58;
let strictAlphanum = GenPass.encodeChars(alphanums, entropy, numChars);
let alphanum = GenPass.hyphenate(strictAlphanum);

let paddingLen = alphanum.length - strictAlphanum.length;
let padding = " ".repeat(paddingLen);

let specials = GenPass.bases.base58 + GenPass.specials.safe;
let special = GenPass.encodeChars(specials, entropy, numChars);
console.info(special, `${padding}\t# base58 + safe specials`);

let specialsLower = GenPass.bases.base32_crockford + GenPass.specials.safe;
let specialLower = GenPass.encodeChars(specialsLower, entropy, numChars);
console.info(specialLower, `${padding}\t# base32 + safe specials`);

console.info(alphanum, `\t# base58`);

let alphanumsLower = GenPass.bases.base32_crockford;
let alphanumLower = GenPass.encodeChars(alphanumsLower, entropy, numChars);
alphanumLower = GenPass.hyphenate(alphanumLower);
console.info(alphanumLower, `\t# base32`);

let hexs = GenPass.bases.hex;
let hex = GenPass.encodeChars(hexs, entropy, numChars);
hex = GenPass.hyphenate(hex);
console.info(hex, `\t# hex`);
