import * as crypto from './crypto'

declare module 'hivecrypt'

export function decode(private_key: string, memo: string): string
export function encode(private_key: string, public_key: string, memo: string, testNonce?: string): string
export const randomWif = crypto.randomWif
export const PublicKey = crypto.PublicKey
export const PrivateKey = crypto.PrivateKey