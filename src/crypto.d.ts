export class PublicKey {
    constructor(key: Buffer, prefix?: string)
    static fromBuffer(key: Buffer): { key: Buffer }
    static fromString(wif: string): PublicKey
    toString(): string
    static from(value: PublicKey | string): PublicKey
}

export class PrivateKey {
    constructor(key: Buffer)
    static fromString(wif: string): PrivateKey
    createPublic(prefix?: string): PublicKey
    toString(): string
    get_shared_secret(public_key: PublicKey): Buffer
}

export const cryptoUtils: {
    decodePrivate: (encodedKey: string) => Buffer,
    doubleSha256: (input: Buffer | string) => Buffer,
    encodePrivate: (key: Buffer) => string,
    ripemd160: (input: Buffer | string) => Buffer,
    sha256: (input: Buffer | string) => Buffer,
    sha512: (input: Buffer | string) => Buffer
}

export function randomWif(): string