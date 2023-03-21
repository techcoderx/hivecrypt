# Hivecrypt

A small JavaScript module for Hive memo encryption and decryption.

Adapted from [this pull request](https://peakd.com/hive-139531/@tngflx/contribution-to-dhive-added-memo-encryption-and-decrypt-feature) that was ~~never~~ merged into [dhive](https://gitlab.syncad.com/hive/dhive). Implemented using [Crypto-JS](https://github.com/brix/crypto-js) such that it is compatible with all JavaScript environments including Electron JS apps.

#### Why was this created?

I needed a way to encrypt and decrypt messages using Hive posting keys in Electron apps, however the methods provided by [hive-js](https://gitlab.syncad.com/hive/hive-js) are not supported in those environments due to the usage of libraries that are only available in Node JS and browsers natively.

## Installation
#### Node JS
```
npm i hivecrypt
```

Then import it as a module with `const hivecrypt = require('hivecrypt')`.

#### Browser
Include in HTML:
```
<script src="https://unpkg.com/hivecrypt/bin/hivecrypt.min.js"></script>
```
The Hivecrypt methods will be accessible through `window.hivecrypt`.

## Usage
#### Encrypt a memo
```
let encrypted = hivecrypt.encode('5Jprivatekey1','STMpublickey2','#messageToEncrypt')
console.log(encrypted)
```

#### Decrypt a memo
```
let decrypted = hivecrypt.decode('5privatekey','#encryptedMessage')
console.log(decrypted)
```

#### Generate a random WIF-encoded private key
```
let randomWif = hivecrypt.randomWif()
console.log(randomWif) // 5JBBPcSkrsvmAmvmex9aC4NNGvZsU87eePzpbFpD9PZRtgGoBKh
```
