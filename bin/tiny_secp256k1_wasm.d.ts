/* tslint:disable */
/* eslint-disable */
/**
* @param {Buffer} p
* @returns {boolean}
*/
export function isPoint(p: Buffer): boolean;
/**
* @param {Buffer} p
* @returns {boolean}
*/
export function isPointCompressed(p: Buffer): boolean;
/**
* @param {Buffer} x
* @returns {boolean}
*/
export function isPrivate(x: Buffer): boolean;
/**
* @param {Buffer} p_a
* @param {Buffer} p_b
* @param {boolean | undefined} compressed
* @returns {Buffer | null}
*/
export function pointAdd(p_a: Buffer, p_b: Buffer, compressed?: boolean): Buffer | null;
/**
* @param {Buffer} p
* @param {Buffer} tweak
* @param {boolean | undefined} compressed
* @returns {Buffer | null}
*/
export function pointAddScalar(p: Buffer, tweak: Buffer, compressed?: boolean): Buffer | null;
/**
* @param {Buffer} p
* @param {boolean | undefined} compressed
* @returns {Buffer}
*/
export function pointCompress(p: Buffer, compressed?: boolean): Buffer;
/**
* @param {Buffer} d
* @param {boolean | undefined} compressed
* @returns {Buffer}
*/
export function pointFromScalar(d: Buffer, compressed?: boolean): Buffer;
/**
* @param {Buffer} p
* @param {Buffer} tweak
* @param {boolean | undefined} compressed
* @returns {Buffer | null}
*/
export function pointMultiply(p: Buffer, tweak: Buffer, compressed?: boolean): Buffer | null;
/**
* @param {Buffer} d
* @param {Buffer} tweak
* @returns {Buffer | null}
*/
export function privateAdd(d: Buffer, tweak: Buffer): Buffer | null;
/**
* @param {Buffer} d
* @param {Buffer} tweak
* @returns {Buffer | null}
*/
export function privateSub(d: Buffer, tweak: Buffer): Buffer | null;
/**
* @param {Buffer} hash
* @param {Buffer} x
* @returns {Buffer}
*/
export function sign(hash: Buffer, x: Buffer): Buffer;
/**
* @param {Buffer} hash
* @param {Buffer} x
* @param {Buffer | undefined} add_data
* @returns {Buffer}
*/
export function signWithEntropy(hash: Buffer, x: Buffer, add_data?: Buffer): Buffer;
/**
* @param {Buffer} hash
* @param {Buffer} qBuffer | null
* @param {Buffer} signature
* @param {boolean | undefined} strict
* @returns {boolean}
*/
export function verify(hash: Buffer, q: Buffer, signature: Buffer, strict?: boolean): boolean;
