const crypto = require("./crypto");
const HexBuffer = require("./hexBuffer");
const UInt32Serializer = (buffer, data) => {
    buffer.writeUint32(data);
};
const UInt64Serializer = (buffer, data) => {
    buffer.writeUint64(data);
};
const PublicKeySerializer = (buffer, data) => {
    if (data === null ||
        (typeof data === 'string' &&
            data.endsWith('1111111111111111111111111111111114T1Anm'))) {
        buffer.append(Buffer.alloc(33, 0));
    }
    else {
        buffer.append(crypto.PublicKey.from(data).key);
    }
};
const BinarySerializer = (size) => (buffer, data) => {
    data = HexBuffer.from(data);
    const len = data.buffer.length;
    if (size) {
        if (len !== size) {
            throw new Error(`Unable to serialize binary. Expected ${size} bytes, got ${len}`);
        }
    }
    else {
        buffer.writeVarint32(len);
    }
    buffer.append(data.buffer);
};
const ObjectSerializer = (keySerializers) => (buffer, data) => {
    for (const [key, serializer] of keySerializers) {
        try {
            serializer(buffer, data[key]);
        }
        catch (error) {
            error.message = `${key}: ${error.message}`;
            throw error;
        }
    }
};
const EncryptedMemoSerializer = ObjectSerializer([
    ['from', PublicKeySerializer],
    ['to', PublicKeySerializer],
    ['nonce', UInt64Serializer],
    ['check', UInt32Serializer],
    ['encrypted', BinarySerializer()]
]);

module.exports.Types = {
    Binary: BinarySerializer,
    EncryptedMemo: EncryptedMemoSerializer,
    Object: ObjectSerializer,
    PublicKey: PublicKeySerializer,
    UInt32: UInt32Serializer,
    UInt64: UInt64Serializer,
};
