/* tslint:disable */
/* eslint-disable */
export function isPoint(p: Buffer): boolean;
export function isPointCompressed(p: Buffer): boolean;
export function isPrivate(x: Buffer): boolean;
export function pointAdd(pA: Buffer, pB: Buffer, compressed?: boolean): Uint8Array | null;
export function pointAddScalar (p: Buffer, tweak: Buffer, compressed?: boolean): Uint8Array | null;
export function pointCompress (p: Buffer, compressed?: boolean): Uint8Array;
export function pointFromScalar (d: Buffer, compressed?: boolean): Uint8Array;
export function pointMultiply (p: Buffer, tweak: Buffer, compressed?: boolean): Uint8Array | null;
export function privateAdd (d: Buffer, tweak: Buffer): Uint8Array | null;
export function privateSub (d: Buffer, tweak: Buffer): Uint8Array | null;
export function sign (hash: Buffer, x: Buffer): Uint8Array;
export function signWithEntropy (hash: Buffer, x: Buffer, addData?: Buffer): Uint8Array;
export function verify (hash: Buffer, q: Buffer, signature: Buffer, strict?: boolean): boolean;
