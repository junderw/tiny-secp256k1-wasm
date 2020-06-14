/* tslint:disable */
/* eslint-disable */
export function isPoint(p: Buffer): boolean;
export function isPointCompressed(p: Buffer): boolean;
export function isPrivate(x: Buffer): boolean;
export function pointAdd(pA: Buffer, pB: Buffer, compressed?: boolean): Buffer | null;
export function pointAddScalar (p: Buffer, tweak: Buffer, compressed?: boolean): Buffer | null;
export function pointCompress (p: Buffer, compressed?: boolean): Buffer;
export function pointFromScalar (d: Buffer, compressed?: boolean): Buffer;
export function pointMultiply (p: Buffer, tweak: Buffer, compressed?: boolean): Buffer | null;
export function privateAdd (d: Buffer, tweak: Buffer): Buffer | null;
export function privateSub (d: Buffer, tweak: Buffer): Buffer | null;
export function sign (hash: Buffer, x: Buffer): Buffer;
export function signWithEntropy (hash: Buffer, x: Buffer, addData?: Buffer): Buffer;
export function verify (hash: Buffer, q: Buffer, signature: Buffer, strict?: boolean): boolean;
