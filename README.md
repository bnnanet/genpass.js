# [genpass.js](https://github.com/bnnanet/genpass.js)

A Sane, Self-Hosted Password Generator

> ```js
> function generatePassword() {
>   // chosen by fair dice roll.
>   // guaranteed to be random.
>   return "(9!q6r48w,bP,d=M";
> }
> ```

<img width="889" alt="GenPass Live Demo Screenshot" src="https://github.com/user-attachments/assets/fd44d478-1bb1-4226-9ecd-ffb46fdae696" />

## Features

- Sane defaults (Base58 + Safe special characters)
- Options for Base62, Base58, Base36, Base32 (Crockford), and Hex
- or use your own custom character set
- Choose which special characters
- Choose length by Character count or Bit entropy

## JavaScript

```sh
npm install --save @root/genpass
```

```js
import GenPass from "@root/genpass";

let entropy = GenPass.generatePaddedBytes();
let charset = GenPass.bases.base58 + GenPass.specials.safe;
let password = GenPass.encodeChars(charset, entropy, 16);
console.info(password);
```

## Self-Host

1. Clone to your sites directory
   ```sh
   mkdir -p ./srv/www/
   pushd ./srv/www/
   git clone https://github.com/bnnanet/genpass.js.git \
       --branch gh-pages --depth 1 \
       ./genpass.example.com
   ```
2. Add to your `Caddyfile` config

   ```Caddyfile
   genpass.example.com {
        encode gzip zstd

        file_server {
                root ./genpass.example.com/
        }
   }
   ```

3. Install caddy and serviceman, if needed

   ```sh
   curl https://webinstall.dev/webi | sh
   source ~/.config/envman/PATH.env

   webi caddy serviceman
   ```

4. Add to system services
   ```sh
   serviceman add -- caddy run --config ./Caddyfile --adapter caddyfile
   ```

## API Notes

- `GenPass.hypenate(str)` has somewhat arbitrary rules that may change
- `GenPass.specials.safe` is based on personal experience and may change
