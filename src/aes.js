const CryptoJS = require('crypto-js')
const randomBytes = require('randombytes')
// const assert = require("assert");
const ByteBuffer = require('bytebuffer');
const { cryptoUtils } = require('./crypto')
const Long = ByteBuffer.Long;
/**
    Spec: https://hive.blog/steem/@dantheman/how-to-encrypt-a-memo-when-transferring-steem
    @throws {Error|TypeError} - "Invalid Key, ..."
    @arg {PrivateKey} private_key - required and used for decryption
    @arg {PublicKey} public_key - required and used to calcualte the shared secret

    @return {object}
    @property {string} nonce - random or unique uint64, provides entropy when re-using the same private/public keys.
    @property {Buffer} message - Plain text message
    @property {number} checksum - shared secret checksum
*/
function encrypt(private_key, public_key, message, nonce = uniqueNonce()) {
    // Change message to varint32 prefixed encoded string
    const mbuf = new ByteBuffer(ByteBuffer.DEFAULT_CAPACITY, ByteBuffer.LITTLE_ENDIAN);
    mbuf.writeVString(message);
    message = Buffer.from(mbuf.flip().toBinary());
    return crypt(private_key, public_key, nonce, message);
}

/**
    Spec: http://localhost:3002/steem/@dantheman/how-to-encrypt-a-memo-when-transferring-steem
    @arg {PrivateKey} private_key - required and used for decryption
    @arg {PublicKey} public_key - required and used to calcualte the shared secret
    @arg {string} nonce - random or unique uint64, provides entropy when re-using the same private/public keys.
    @arg {Buffer} message - Encrypted or plain text message
    @arg {number} checksum - shared secret checksum
    @throws {Error|TypeError} - "Invalid Key, ..."
    @return {Buffer} - message
*/
function decrypt(private_key, public_key, nonce, message, checksum) {
    return crypt(private_key, public_key, nonce, message, checksum).message;
}

/**
    @arg {Buffer} message - Encrypted or plain text message (see checksum)
    @arg {number} checksum - shared secret checksum (null to encrypt, non-null to decrypt)
*/
function crypt(private_key, public_key, nonce, message, checksum) {
    nonce = toLongObj(nonce);
    // Appending nonce to buffer "ebuf" and rehash with sha512
    let S = private_key.get_shared_secret(public_key)
    let ebuf = new ByteBuffer(ByteBuffer.DEFAULT_CAPACITY, ByteBuffer.LITTLE_ENDIAN);
    ebuf.writeUint64(nonce);
    // ebuf.append(aesKey.toString('binary'), 'binary');
    ebuf.append(S.toString('binary'),'binary')
    ebuf = new Buffer.from(ebuf.copy(0, ebuf.offset).toBinary(), 'binary')
    // const encryption_key = Buffer.from(CryptoJS.SHA512(ebuf).toString(CryptoJS.enc.Hex),'hex')
    // const encryption_key = createHash('sha512').update(ebuf).digest()
    const encryption_key = cryptoUtils.sha512(ebuf)
    const iv = encryption_key.slice(32, 48);
    const tag = encryption_key.slice(0, 32);
    // check if first 64 bit of sha256 hash treated as uint64_t truncated to 32 bits.
    // let check = CryptoJS.SHA256(encryption_key).toString()
    // let check = createHash('sha256').update(encryption_key).digest()
    let check = cryptoUtils.sha256(encryption_key)
    check = check.slice(0, 4);
    const cbuf = ByteBuffer.fromBinary(check.toString('binary'), ByteBuffer.DEFAULT_CAPACITY, ByteBuffer.LITTLE_ENDIAN);
    check = cbuf.readUint32();
    if (checksum) {
        if (check !== checksum) {
            throw new Error('Invalid nonce');
        }
        message = cryptoJsDecrypt(message, tag, iv);
    }
    else {
        message = cryptoJsEncrypt(message, tag, iv);
    }
    return { nonce, message, checksum: check };
}
/** This method does not use a checksum, the returned data must be validated some other way.
    @arg {string|Buffer} ciphertext - binary format
    @return {Buffer}
*/
function cryptoJsDecrypt(message, key, iv) {
    // assert(message, 'Missing cipher text');
    message = toBinaryBuffer(message)
    const waMessage = CryptoJS.lib.WordArray.create(message)
    const waKey = CryptoJS.lib.WordArray.create(key)
    const waIv = CryptoJS.lib.WordArray.create(iv)
    const cipherParams = CryptoJS.lib.CipherParams.create({
        ciphertext: waMessage,
        key: waKey,
        iv: waIv,
        mode: CryptoJS.mode.CBC,
        algorithm: CryptoJS.algo.AES,
        padding: CryptoJS.pad.Pkcs7,
        blockSize: 4,
        formatter: CryptoJS.format.OpenSSL
    })
    const decipher = CryptoJS.AES.decrypt(cipherParams, waKey, {
        iv: waIv,
        mode: CryptoJS.mode.CBC
    })
    return Buffer.from(decipher.toString(),'hex');
    // const decipher = CryptoOld.createDecipheriv('aes-256-cbc', key, iv)
    // message = Buffer.concat([decipher.update(message), decipher.final()])
    // return message
}
/** This method does not use a checksum, the returned data must be validated some other way.
    @arg {string|Buffer} plaintext - binary format
    @return {Buffer} binary
*/
function cryptoJsEncrypt(message, key, iv) {
    // assert(message, 'Missing plain text');
    message = toBinaryBuffer(message)
    const waMessage = CryptoJS.lib.WordArray.create(message)
    const cipher = CryptoJS.AES.encrypt(waMessage, CryptoJS.lib.WordArray.create(key), {
        iv: CryptoJS.lib.WordArray.create(iv),
        mode: CryptoJS.mode.CBC
    })
    return Buffer.from(cipher.ciphertext.toString(),'hex')
    // const cipher = CryptoOld.createCipheriv('aes-256-cbc', key, iv)
    // message = Buffer.concat([cipher.update(message), cipher.final()])
    // return message
}
/** @return {string} unique 64 bit unsigned number string.  Being time based,
 * this is careful to never choose the same nonce twice.  This value could
 * clsbe recorded in the blockchain for a long time.
*/
let unique_nonce_entropy = null;
function uniqueNonce() {
    if (unique_nonce_entropy === null) {
        const uint8randomArr = new Uint8Array(2);
        for (let i = 0; i < 2; ++i) {
            uint8randomArr[i] = randomBytes(2).readUInt8(i);
        }
        unique_nonce_entropy = uint8randomArr[0] << 8 | uint8randomArr[1];
    }
    let long = Long.fromNumber(Date.now());
    const entropy = ++unique_nonce_entropy % 0xFFFF;
    long = long.shiftLeft(16).or(Long.fromNumber(entropy));
    return long.toString();
}
const toLongObj = o => (o ? Long.isLong(o) ? o : Long.fromString(o) : o)
const toBinaryBuffer = o => (o ? Buffer.isBuffer(o) ? o : new Buffer.from(o, 'binary') : o)

module.exports = {
    encrypt,
    decrypt
}