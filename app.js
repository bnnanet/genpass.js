import GenPass from "genpass";

/** @type {HTMLElement} */ //@ts-expect-error
let $passwordDisplay = document.querySelector("#passwordDisplay");
/** @type {HTMLButtonElement} */ //@ts-expect-error
let $generateButton = document.querySelector("#generateButton");
/** @type {HTMLInputElement} */ //@ts-expect-error
let $baseCharset = document.querySelector('[name="baseCharset"]');
/** @type {HTMLInputElement} */ //@ts-expect-error
let $specialChars = document.querySelector('[name="specialChars"]');
/** @type {HTMLInputElement} */ //@ts-expect-error
let $includeSpecials = document.querySelector("#includeSpecials");
/** @type {HTMLInputElement} */ //@ts-expect-error
let $excludeIdentical = document.querySelector("#excludeIdentical");
/** @type {Array<HTMLInputElement>} */ //@ts-expect-error
let $blacklists = document.querySelectorAll("[data-id=blacklists] input");
/** @type {HTMLElement} */ //@ts-expect-error
let $base = document.querySelector('[data-id="base"]');
/** @type {HTMLElement} */ //@ts-expect-error
let $charset = document.querySelector('[data-id="charset"]');
/** @type {HTMLInputElement} */ //@ts-expect-error
let $bits = document.querySelector('[name="bits"]');
/** @type {HTMLElement} */ //@ts-expect-error
let $bitsCount = document.querySelector('[data-id="bits"]');
/** @type {HTMLInputElement} */ //@ts-expect-error
let $chars = document.querySelector('[name="chars"]');
/** @type {HTMLElement} */ //@ts-expect-error
let $charsCount = document.querySelector('[data-id="chars"]');

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
  if ($excludeIdentical.checked) {
    blacklist += "lIO0"; // base58
  }

  return blacklist;
}

function customizeCharset() {
  let charset = `${$baseCharset.value}${$specialChars.value}`;
  $charset.textContent = charset;
  $base.textContent = charset.length.toString();

  updateMinCharLen();
  generatePassword();
}

function updateCharset() {
  /** @type {HTMLInputElement} */ //@ts-expect-error
  let $selectedBase = document.querySelector('[name="base"]:checked');
  let basename = $selectedBase.value;
  //@ts-expect-error
  let base = GenPass.bases[basename];
  let specials = "";

  if ($excludeIdentical.checked) {
    let exclusions = "IlO0";
    base = GenPass.calculateAllowed(base, exclusions);
  }

  if ($includeSpecials.checked) {
    let exclusions = getBlacklist();
    specials = GenPass.calculateAllowed(GenPass.specials, exclusions);
  }

  let charset = base + specials;

  $baseCharset.value = base;
  $specialChars.value = specials;
  $charset.textContent = charset;
  $base.textContent = charset.length.toString();
}

function _updateMinBits() {
  let base = $charset.textContent?.length || 74;
  let numBits = parseInt($bits.value, 10);
  let numChars = GenPass.getMinChars(base, numBits);

  $charsCount.textContent = numChars.toString();
  $chars.value = numChars.toString();

  $bitsCount.textContent = $bits.value;
}

function updateMinBits() {
  _updateMinBits();
  _updateMinCharLen();
  generatePassword();
}

function refreshAll() {
  updateCharset();
  updateMinCharLen();
  generatePassword();
}

function generatePassword() {
  let charset = $charset.textContent || "";
  let n = parseInt($chars.value, 10);
  $passwordDisplay.textContent = GenPass.generateChars(charset, n);
}

function _updateMinCharLen() {
  let base = $charset.textContent?.length || 0;
  let numChars = parseInt($chars.value, 10);
  let numBits = GenPass.getMinBits(base, numChars);

  $bitsCount.textContent = numBits.toString();
  $bits.value = numBits.toString();

  $charsCount.textContent = $chars.value;
}

function updateMinCharLen() {
  _updateMinCharLen();
  _updateMinBits();
  generatePassword();
}

async function main() {
  let $checks = document.querySelectorAll('input[type="checkbox"]');
  for (let $check of $checks) {
    $check.addEventListener("change", refreshAll);
  }

  $bits.addEventListener("input", updateMinBits);
  $chars.addEventListener("input", updateMinCharLen);

  $baseCharset.addEventListener("change", customizeCharset);
  $specialChars.addEventListener("change", customizeCharset);

  $generateButton.addEventListener("click", generatePassword);

  updateCharset();
  updateMinCharLen();
  updateMinBits();
  generatePassword();
}

main().catch(handleError);

/** @param {Error} err */
function handleError(err) {
  console.error("main() caught uncaught error:");
  console.error(err.message);
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
