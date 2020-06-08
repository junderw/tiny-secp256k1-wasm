const pkg = require('../pkg');
const ecc = require('tiny-secp256k1/js');
const eccNative = require('tiny-secp256k1/native');
const bitcoinTS = require('bitcoin-ts');
const { instantiateSecp256k1 } = bitcoinTS;
const crypto = require('crypto');

const ITER = 1e3;

async function performBench(_sign, name, iter) {
  console.log(`Staring bench for ${name} ${iter} times`);
  const key = crypto.randomBytes(32);
  const hash = crypto.randomBytes(32);
  const before = Date.now();
  for(let i = 0; i < iter; i++) {
    _sign(hash, key)
  }
  const after = Date.now();
  console.log(`Finished ${iter} iterations of ${name} in ${after - before} ms`);
}

async function main(args) {
  const iterations = args[0] || ITER;
  const secp256k1 = await instantiateSecp256k1();
  const secp = pkg.TinySecp.new();
  await performBench(eccNative.sign, 'NATIVE', iterations);
  await performBench(ecc.sign, 'JS', iterations);
  await performBench(secp256k1.signMessageHashCompact, 'BITCOIN-TS WASM', iterations);
  await performBench(secp.sign.bind(secp), 'OUR-WASM', iterations);
}

main(process.argv.slice(2)).catch(err => {
  console.error(err)
  process.exit(err.code || 1)
})
