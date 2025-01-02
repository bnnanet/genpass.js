import GenPass from "genpass";

let passBytes = new Uint8Array(0);

/** @type {HTMLButtonElement} */ //@ts-expect-error
let $generateButton = document.querySelector("#generateButton");
/** @type {HTMLInputElement} */ //@ts-expect-error
let $baseCharset = document.querySelector('[name="baseCharset"]');
/** @type {HTMLInputElement} */ //@ts-expect-error
let $specialChars = document.querySelector('[name="specialChars"]');
/** @type {HTMLInputElement} */ //@ts-expect-error
let $excludeIdentical = document.querySelector("#excludeIdentical");
/** @type {HTMLInputElement} */ //@ts-expect-error
let $includeUppercase = document.querySelector("#includeUppercase");
/** @type {HTMLInputElement} */ //@ts-expect-error
let $hypenateAlphanum = document.querySelector("#hypenateAlphanum");
/** @type {Array<HTMLInputElement>} */ //@ts-expect-error
let $blacklists = document.querySelectorAll("[data-id=blacklists] input");
/** @type {HTMLElement} */ //@ts-expect-error
let $conflictChars = document.querySelector('[data-id="conflict-chars"]');

/** @type {HTMLInputElement} */ //@ts-expect-error
let $bits = document.querySelector('[name="bits"]');
/** @type {HTMLElement} */ //@ts-expect-error
let $bitsCount = document.querySelector('[data-id="bits"]');
/** @type {HTMLInputElement} */ //@ts-expect-error
let $chars = document.querySelector('[name="chars"]');
/** @type {HTMLElement} */ //@ts-expect-error
let $charsCount = document.querySelector('[data-id="chars"]');

let special = {
  numChars: parseInt($chars.value, 10),
  /** @type {HTMLElement} */ //@ts-expect-error
  $base: document.querySelector('[data-id="pw-special"] [data-name="base"]'),
  /** @type {HTMLElement} */ //@ts-expect-error
  $entropy: document.querySelector(
    '[data-id="pw-special"] [data-name="entropy"]',
  ),
  /** @type {HTMLElement} */ //@ts-expect-error
  $charset: document.querySelector(
    '[data-id="pw-special"] [data-name="charset"]',
  ),
  /** @type {HTMLElement} */ //@ts-expect-error
  $password: document.querySelector(
    `[data-id="pw-special"] [data-name="password"]`,
  ),
};

let plain = {
  numChars: parseInt($chars.value, 10),
  /** @type {HTMLElement} */ //@ts-expect-error
  $base: document.querySelector('[data-id="pw-alphanum"] [data-name="base"]'),
  /** @type {HTMLElement} */ //@ts-expect-error
  $bits: document.querySelector(
    '[data-id="pw-alphanum"] [data-name="entropy"]',
  ),
  /** @type {HTMLElement} */ //@ts-expect-error
  $charset: document.querySelector(
    '[data-id="pw-alphanum"] [data-name="charset"]',
  ),
  /** @type {HTMLElement} */ //@ts-expect-error
  $password: document.querySelector(
    `[data-id="pw-alphanum"] [data-name="password"]`,
  ),
};

let hex = {
  numChars: parseInt($chars.value, 10),
  /** @type {HTMLElement} */ //@ts-expect-error
  $base: document.querySelector('[data-id="pw-hex"] [data-name="base"]'),
  /** @type {HTMLElement} */ //@ts-expect-error
  $bits: document.querySelector('[data-id="pw-hex"] [data-name="entropy"]'),
  /** @type {HTMLElement} */ //@ts-expect-error
  $charset: document.querySelector('[data-id="pw-hex"] [data-name="charset"]'),
  /** @type {HTMLElement} */ //@ts-expect-error
  $password: document.querySelector(
    `[data-id="pw-hex"] [data-name="password"]`,
  ),
};

function getBlacklist() {
  let blacklist = "";
  for (let $blacklist of $blacklists) {
    if (!$blacklist.checked) {
      continue;
    }

    //@ts-expect-error
    let partial = GenPass.blacklists[$blacklist.value];
    if (!partial) {
      throw new Error(
        `'${$blacklist.value}' is not a valid compatibility category`,
      );
    }

    blacklist += partial;
  }

  if (!$includeUppercase.checked) {
    blacklist += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  }
  if ($excludeIdentical.checked) {
    if ($includeUppercase.checked) {
      blacklist += "lIO0"; // base58
    } else {
      blacklist += "liou"; // crockford base32
    }
  }

  return blacklist;
}

function customizeCharset() {
  let charset = `${$baseCharset.value}${$specialChars.value}`;
  special.$charset.textContent = charset;
  special.$base.textContent = charset.length.toString();

  plain.$charset.textContent = $baseCharset.value;
  plain.$base.textContent = $baseCharset.value.length.toString();

  updateMinCharLen();
}

function updateCharset() {
  /** @type {HTMLInputElement} */ //@ts-expect-error
  let $selectedBase = document.querySelector('[name="base"]:checked');
  let basename = $selectedBase.value;
  //@ts-expect-error
  let base = GenPass.bases[basename];

  let blacklist = "";
  if (!$includeUppercase.checked) {
    blacklist += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  }
  if ($excludeIdentical.checked) {
    if ($includeUppercase.checked) {
      blacklist += "lIO0"; // base58
    } else {
      blacklist += "liou"; // crockford base32
    }
  }

  let specials = "";
  {
    let exclusions = getBlacklist();
    specials = GenPass.calculateAllowed(GenPass.specials, exclusions);
  }

  base = GenPass.calculateAllowed(base, blacklist);
  let charset = base + specials;

  $baseCharset.value = base;
  $specialChars.value = specials;

  special.$charset.textContent = charset;
  special.$base.textContent = charset.length.toString();

  plain.$charset.textContent = $baseCharset.value;
  plain.$base.textContent = $baseCharset.value.length.toString();
}

function updateMinBits() {
  let specialBase = special.$charset.textContent?.length || 74;
  let specialNumBits = parseInt($bits.value, 10);
  special.numChars = GenPass.getMinChars(specialBase, specialNumBits);
  special.$entropy.textContent = `${special.numChars}-char`;

  let plainBase = plain.$charset.textContent?.length || 74;
  let plainNumBits = parseInt($bits.value, 10);
  plain.numChars = GenPass.getMinChars(plainBase, plainNumBits);
  plain.$bits.textContent = `${plain.numChars}-char`;

  let hexBase = hex.$charset.textContent?.length || 1;
  let hexNumBits = parseInt($bits.value, 10);
  hex.numChars = GenPass.getMinChars(hexBase, hexNumBits);
  hex.$bits.textContent = `${hex.numChars}-char`;

  $bitsCount.textContent = $bits.value;

  encodePassword();
}

function updateMinCharLen() {
  let specialBase = special.$charset.textContent?.length || 1;
  special.numChars = parseInt($chars.value, 10);
  let specialNumBits = GenPass.getMinBits(specialBase, special.numChars);
  special.$entropy.textContent = `${specialNumBits}-bit`;

  let plainBase = plain.$charset.textContent?.length || 1;
  plain.numChars = parseInt($chars.value, 10);
  let plainNumBits = GenPass.getMinBits(plainBase, plain.numChars);
  plain.$bits.textContent = `${plainNumBits}-bit`;

  let hexBase = hex.$charset.textContent?.length || 1;
  hex.numChars = parseInt($chars.value, 10);
  let hexNumBits = GenPass.getMinBits(hexBase, hex.numChars);
  hex.$bits.textContent = `${hexNumBits}-bit`;

  $charsCount.textContent = $chars.value;
  encodePassword();
}

function updateOptions() {
  if ($includeUppercase.checked) {
    $conflictChars.textContent = "I,l,0,O";
  } else {
    $conflictChars.textContent = "i,l,0,u";
  }
  updateCharset();
  encodePassword();
}

function generateNewPassword() {
  passBytes = GenPass.generateBytes();

  encodePassword();
}

function encodePassword() {
  let specialCharset = special.$charset.textContent || "";
  special.$password.textContent = GenPass.encodeChars(
    specialCharset,
    passBytes,
    special.numChars,
  );

  let plainCharset = plain.$charset.textContent || "";
  let plainPass = GenPass.encodeChars(plainCharset, passBytes, plain.numChars);
  if ($hypenateAlphanum.checked) {
    plainPass = formatAlphanum(plainPass);
  }
  plain.$password.textContent = plainPass;

  let hexCharset = hex.$charset.textContent || "";
  let hexPass = GenPass.encodeChars(hexCharset, passBytes, hex.numChars);
  if ($hypenateAlphanum.checked) {
    hexPass = formatAlphanum(hexPass);
  }
  hex.$password.textContent = hexPass;
}

/**
 * Formats an input string based on its length.
 *
 * @param {string} input - The string to be formatted.
 * @returns {string} - The formatted string.
 */
function formatAlphanum(input) {
  /* jshint maxcomplexity: 30 */
  const length = input.length;

  // TODO: generalize this a bit
  // it's something like
  // if divisible by 3 or 4 and the result is >= 3 and <=7, group it
  // if greater than 6 and divisible by 2, group it
  // if it's got a remainder of 1 or 2, group it with middle(s) longer

  if (length < 6) {
    return input;
  }

  if (length === 6 || length === 9) {
    let matches = input.match(/.{1,3}/g);
    // xxx-xxx or xxx-xxx-xxx
    //@ts-expect-error
    return matches.join("-");
  }

  if (length === 8 || length === 12 || length === 16 || length === 20) {
    let matches = input.match(/.{1,4}/g);
    // xxxx-xxxx or xxxx-xxxx-xxxx
    //@ts-expect-error
    return matches.join("-");
  }

  if (length === 10 || length === 15 || length === 25 || length === 35) {
    let matches = input.match(/.{1,5}/g);
    // xxxxx-xxxxx-xxxxx
    //@ts-expect-error
    return matches.join("-");
  }

  if (length === 18 || length === 24 || length === 30) {
    let matches = input.match(/.{1,6}/g);
    // xxxxx-xxxxx-xxxxx
    //@ts-expect-error
    return matches.join("-");
  }

  if (
    length === 14 ||
    length === 21 ||
    length === 28 ||
    length === 35 ||
    length === 42
  ) {
    let matches = input.match(/.{1,7}/g);
    // xxxxx-xxxxx-xxxxx
    //@ts-expect-error
    return matches.join("-");
  }

  if (length === 24 || length === 32 || length === 40) {
    let matches = input.match(/.{1,8}/g);
    // xxxxxxxx-xxxxxxxx-xxxxxxxx
    //@ts-expect-error
    return matches.join("-");
  }

  if (length === 27 || length === 36) {
    let matches = input.match(/.{1,9}/g);
    // xxxxxxxxx-xxxxxxxxx-xxxxxxxxx
    //@ts-expect-error
    return matches.join("-");
  }

  return input;
}

async function main() {
  let $checks = document.querySelectorAll('input[type="checkbox"]');
  for (let $check of $checks) {
    $check.addEventListener("change", updateOptions);
  }

  $bits.addEventListener("input", updateMinBits);
  $chars.addEventListener("input", updateMinCharLen);

  $baseCharset.addEventListener("change", customizeCharset);
  $specialChars.addEventListener("change", customizeCharset);

  $generateButton.addEventListener("click", generateNewPassword);

  updateCharset();
  generateNewPassword();
  updateMinCharLen();
  updateOptions();
}

main().catch(handleError);

/** @param {Error} err */
function handleError(err) {
  console.error("main() caught uncaught error:");
  console.error(err);
  window.alert(
    `Error:\none of our developers let a bug slip through the cracks:\n\n${err.message}`,
  );
}

window.onerror = function (message, url, lineNumber, columnNumber, err) {
  if (!err) {
    err = new Error(
      `"somebody pulled a 'throw undefined', somewhere:\n message:'${message}' \nurl:'${url}' \nlineNumber:'${lineNumber}' \ncolumnNumber:'${columnNumber}'`,
    );
  }
  handleError(err);
};

window.onunhandledrejection = async function (event) {
  let err = event.reason;
  if (!err) {
    let msg = `developer error (not your fault): error is missing error object`;
    err = new Error(msg);
  }
  handleError(err);
};
