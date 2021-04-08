/**
 * @file Hive crypto helpers.
 * @author Johan Nordberg <code@johan-nordberg.com>
 * @license
 * Copyright (c) 2017 Johan Nordberg. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 *  1. Redistribution of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 *
 *  2. Redistribution in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *  3. Neither the name of the copyright holder nor the names of its contributors
 *     may be used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * You acknowledge that this software is not designed, licensed or intended for use
 * in the design, construction, operation or maintenance of any military facility.
 */
const assert = require("assert");
const CryptoJS = require('crypto-js')
const bs58 = require("bs58");
const secp256k1 = require("secp256k1");
const hkdf = require("futoin-hkdf")
const randomBytes = require('randombytes')
/**
 * Network id used in WIF-encoding.
 */
const NETWORK_ID = Buffer.from([0x80]);
/**
 * Return ripemd160 hash of input.
 */
function ripemd160(input) {
    // https://github.com/mahdiyari/hive-tx-js/blob/master/helpers/crypto.js
    if (typeof input !== 'string')
        input = CryptoJS.lib.WordArray.create(input)
    const hash = Buffer.from(CryptoJS.RIPEMD160(input).toString(CryptoJS.enc.Hex),'hex')
    return hash
    // return CryptoOld.createHash('rmd160').update(input).digest()
}
/**
 * Return sha256 hash of input.
 */
function sha256(input) {
    // https://github.com/mahdiyari/hive-tx-js/blob/master/helpers/crypto.js
    if (typeof input !== 'string')
        input = CryptoJS.lib.WordArray.create(input)
    const hash = Buffer.from(CryptoJS.SHA256(input).toString(CryptoJS.enc.Hex),'hex')
    return hash
    // return CryptoOld.createHash('sha256').update(input).digest()
}
/**
 * Return sha512 hash of input. 
 */
function sha512(input) {
    if (typeof input !== 'string')
        input = CryptoJS.lib.WordArray.create(input)
    const hash = Buffer.from(CryptoJS.SHA256(input).toString(CryptoJS.enc.Hex),'hex')
    return hash
    // return CryptoOld.createHash('sha512').update(input).digest()
}
/**
 * Return 2-round sha256 hash of input.
 */
function doubleSha256(input) {
    return sha256(sha256(input));
}
/**
 * Encode bs58+ripemd160-checksum encoded public key.
 */
function encodePublic(key, prefix) {
    const checksum = ripemd160(key)
    return prefix + bs58.encode(Buffer.concat([key, checksum.slice(0, 4)]))
}
/**
 * Decode bs58+ripemd160-checksum encoded public key.
 */
function decodePublic(encodedKey) {
    const prefix = encodedKey.slice(0, 3);
    assert.equal(prefix.length, 3, "public key invalid prefix");
    encodedKey = encodedKey.slice(3);
    const buffer = bs58.decode(encodedKey);
    const checksum = buffer.slice(-4);
    const key = buffer.slice(0, -4);
    const checksumVerify = ripemd160(key).slice(0, 4);
    assert.deepEqual(checksumVerify, checksum, "public key checksum mismatch");
    return { key, prefix };
}
/**
 * Encode bs58+doubleSha256-checksum private key.
 */
function encodePrivate(key) {
    assert.equal(key.readUInt8(0), 0x80, "private key network id mismatch");
    const checksum = doubleSha256(key);
    return bs58.encode(Buffer.concat([key, checksum.slice(0, 4)]));
}
/**
 * Decode bs58+doubleSha256-checksum encoded private key.
 */
function decodePrivate(encodedKey) {
    const buffer = bs58.decode(encodedKey);
    assert.deepEqual(buffer.slice(0, 1), NETWORK_ID, "private key network id mismatch");
    const checksum = buffer.slice(-4);
    const key = buffer.slice(0, -4);
    const checksumVerify = doubleSha256(key).slice(0, 4);
    assert.deepEqual(checksumVerify, checksum, "private key checksum mismatch");
    return key;
}

/**
 * ECDSA (secp256k1) public key.
 */
class PublicKey {
    constructor(key, prefix = 'STM') {
        this.key = key;
        this.prefix = prefix;
        this.uncompressed = Buffer.from(secp256k1.publicKeyConvert(key, false));
        assert(secp256k1.publicKeyVerify(key), "invalid public key");
    }
    static fromBuffer(key) {
        assert(secp256k1.publicKeyVerify(key), "invalid buffer as public key");
        return { key };
    }
    /**
     * Create a new instance from a WIF-encoded key.
     */
    static fromString(wif) {
        const { key, prefix } = decodePublic(wif);
        return new PublicKey(key, prefix);
    }
    /**
     * Convert public key buffer to WIF encoding
     */
    toString() {
        return encodePublic(this.key,this.prefix)
    }
    /**
     * Create a new instance.
     */
    static from(value) {
        if (value instanceof PublicKey) {
            return value;
        }
        else {
            return PublicKey.fromString(value);
        }
    }
    decapsulate(priv) {
        const master = Buffer.concat([
            this.uncompressed,
            priv.multiply(this),
        ]);
        return hkdf(master, 64, {
            hash: "SHA-512",
        });
    }
}

/**
 * ECDSA (secp256k1) private key.
 */
class PrivateKey {
    constructor(key) {
        this.key = key;
        this.secret = key;
        assert(secp256k1.privateKeyVerify(key), "invalid private key");
    }
    /**
     * Create a new instance from a WIF-encoded key.
     */
    static fromString(wif) {
        return new PrivateKey(decodePrivate(wif).slice(1));
    }
    /**
     * HMAC based key derivation function
     * @param pub recipient publickey
     */
    encapsulate(pub) {
        const master = Buffer.concat([
            pub.uncompressed,
            this.multiply(pub),
        ]);
        return hkdf(master, 64, {
            hash: "SHA-512",
        });
    }
    multiply(pub) {
        return Buffer.from(secp256k1.publicKeyTweakMul(pub.key, this.secret, false));
    }
    /**
     * Derive the public key for this private key.
     */
    createPublic(prefix) {
        return new PublicKey(secp256k1.publicKeyCreate(this.key), prefix);
    }

    /** Return a WIF-encoded representation of the key. */
    toString () {
        return encodePrivate(Buffer.concat([NETWORK_ID, this.key]))
    }
}

function randomWif() {
    return new PrivateKey(randomBytes(32)).toString()
}

module.exports = {
    PublicKey,
    PrivateKey,
    cryptoUtils: {
        decodePrivate,
        doubleSha256,
        encodePrivate,
        ripemd160,
        sha256,
        sha512
    },
    randomWif
}
