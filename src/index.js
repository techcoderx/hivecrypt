const crypto = require("./crypto");
const serializer = require("./serializer");
const Aes = require("./aes");
const deserializer = require("./deserializer");
const bs58 = require("bs58");
const ByteBuffer = require("bytebuffer");
/**
 * Memo/Any message encoding using AES (aes-cbc algorithm)
 * @param {Buffer|String} private_key Privatekey of sender
 * @param {Buffer|String}public_key publickey of recipient
 * @param {String}memo message to be encrypted
 */
function encode(private_key, public_key, memo, testNonce) {
    if (!memo.startsWith('#')) {
        return memo;
    }
    memo = memo.substring(1);
    private_key = toPrivateObj(private_key);
    public_key = toPublicObj(public_key);
    const { nonce, message, checksum } = Aes.encrypt(private_key, public_key, memo, testNonce);
    const mbuf = new ByteBuffer(ByteBuffer.DEFAULT_CAPACITY, ByteBuffer.LITTLE_ENDIAN);
    serializer.Types.EncryptedMemo(mbuf, {
        check: checksum,
        encrypted: message,
        from: private_key.createPublic(),
        nonce,
        to: public_key
    });
    mbuf.flip();
    const data = Buffer.from(mbuf.toBuffer(),'binary');
    return '#' + bs58.encode(data);
}
/**
 * Encrypted memo/message decryption
 * @param {Buffer|string}private_key Privatekey of recipient
 * @param {any}memo Encrypted message/memo
 */
function decode(private_key, memo) {
    if (!memo.startsWith('#')) {
        return memo;
    }
    memo = memo.substring(1);
    // checkEncryption()
    private_key = toPrivateObj(private_key);
    memo = bs58.decode(memo);
    memo = deserializer.types.EncryptedMemoD(Buffer.from(memo, 'binary'));
    const { from, to, nonce, check, encrypted } = memo;
    const pubkey = private_key.createPublic().toString();
    const otherpub = pubkey === new crypto.PublicKey(from.key).toString() ? new crypto.PublicKey(to.key) : new crypto.PublicKey(from.key);
    memo = Aes.decrypt(private_key, otherpub, nonce, encrypted, check);
    // remove varint length prefix
    const mbuf = ByteBuffer.fromBinary(memo.toString('binary'), ByteBuffer.LITTLE_ENDIAN);
    try {
        mbuf.mark();
        return '#' + mbuf.readVString();
    }
    catch (e) {
        mbuf.reset();
        // Sender did not length-prefix the memo
        memo = Buffer.from(mbuf.toString('binary'), 'binary').toString('utf-8');
        return '#' + memo;
    }
}
const toPrivateObj = o => (o ? o.key ? o : crypto.PrivateKey.fromString(o) : o /* null or undefined*/);
const toPublicObj = o => (o ? o.key ? o : crypto.PublicKey.fromString(o) : o /* null or undefined*/);

if (typeof window != 'undefined') window.hivecrypt = { decode, encode, randomWif: crypto.randomWif, PublicKey: crypto.PublicKey, PrivateKey: crypto.PrivateKey };
module.exports = { decode, encode, randomWif: crypto.randomWif, PublicKey: crypto.PublicKey, PrivateKey: crypto.PrivateKey };
