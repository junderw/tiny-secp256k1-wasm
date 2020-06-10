const pkg = require('./tiny_secp256k1_wasm');
const wasm = new pkg.TinySecp();

function isPoint (p) {
  return wasm.isPoint(p)
}

function isPointCompressed (p) {
  return wasm.isPointCompressed(p)
}

function isPrivate (x) {
  return wasm.isPrivate(x)
}

function pointAdd (pA, pB, compressed) {
  const result = wasm.pointAdd(pA, pB, compressed)
  return result && Buffer.from(result)
}

function pointAddScalar (p, tweak, compressed) {
  const result = wasm.pointAddScalar(p, tweak, compressed)
  return result && Buffer.from(result)
}

function pointCompress (p, compressed) {
  const result = wasm.pointCompress(p, compressed)
  return result && Buffer.from(result)
}

function pointFromScalar (d, compressed) {
  const result = wasm.pointFromScalar(d, compressed)
  return result && Buffer.from(result)
}

function pointMultiply (p, tweak, compressed) {
  const result = wasm.pointMultiply(p, tweak, compressed)
  return result && Buffer.from(result)
}

function privateAdd (d, tweak) {
  const result = wasm.privateAdd(d, tweak)
  return result && Buffer.from(result)
}

function privateSub (d, tweak) {
  const result = wasm.privateSub(d, tweak)
  return result && Buffer.from(result)
}

function sign (hash, x) {
  const result = wasm.sign(hash, x)
  return result && Buffer.from(result)
}

function signWithEntropy (hash, x, addData) {
  const result = wasm.signWithEntropy(hash, x, addData)
  return result && Buffer.from(result)
}

function verify (hash, q, signature, strict) {
  return wasm.verify(hash, q, signature, strict)
}

module.exports = {
  isPoint,
  isPointCompressed,
  isPrivate,
  pointAdd,
  pointAddScalar,
  pointCompress,
  pointFromScalar,
  pointMultiply,
  privateAdd,
  privateSub,
  sign,
  signWithEntropy,
  verify
}
