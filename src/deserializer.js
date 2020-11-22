const crypto = require("./crypto");
const ByteBuffer = require("bytebuffer");
const PublicKeyDeserializer = (buf) => {
    const c = fixed_buf(buf, 33);
    return crypto.PublicKey.fromBuffer(c);
};
const UInt64Deserializer = (b) => b.readUint64();
const UInt32Deserializer = (b) => b.readUint32();
const BinaryDeserializer = (b) => {
    const len = b.readVarint32();
    const b_copy = b.copy(b.offset, b.offset + len);
    b.skip(len);
    return Buffer.from(b_copy.toBinary(), 'binary');
};
const BufferDeserializer = (keyDeserializers) => (buf) => {
    const obj = {};
    for (const [key, deserializer] of keyDeserializers) {
        try {
            // Decodes a binary encoded string to a ByteBuffer.
            buf = ByteBuffer.fromBinary(buf.toString('binary'), ByteBuffer.LITTLE_ENDIAN);
            obj[key] = deserializer(buf);
        }
        catch (error) {
            error.message = `${key}: ${error.message}`;
            throw error;
        }
    }
    return obj;
};
function fixed_buf(b, len) {
    if (!b) {
        throw Error('No buffer found on first parameter');
    }
    else {
        const b_copy = b.copy(b.offset, b.offset + len);
        b.skip(len);
        return Buffer.from(b_copy.toBinary(), 'binary');
    }
}
const EncryptedMemoDeserializer = BufferDeserializer([
    ['from', PublicKeyDeserializer],
    ['to', PublicKeyDeserializer],
    ['nonce', UInt64Deserializer],
    ['check', UInt32Deserializer],
    ['encrypted', BinaryDeserializer]
]);

module.exports.types = {
    EncryptedMemoD: EncryptedMemoDeserializer
};
