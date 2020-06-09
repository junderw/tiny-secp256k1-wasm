const pkg = require('../pkg');
const ecc = require('tiny-secp256k1/js');
const eccNative = require('tiny-secp256k1/native');
const bitcoinTS = require('bitcoin-ts');
const { instantiateSecp256k1 } = bitcoinTS;
const crypto = require('crypto');

const RANDOM_KEY = crypto.randomBytes(32);
RANDOM_KEY[0] &= 0x7f;
RANDOM_KEY[31] = 0xff; // (lazy) make sure it's not invalid

const RANDOM_HASH = crypto.randomBytes(32);

const PUBKEY_C = eccNative.pointFromScalar(RANDOM_KEY, true);
const PUBKEY_UC = eccNative.pointCompress(PUBKEY_C, false);

async function performBench(func, args, typeName, funcName, iter) {
  console.log(`Starting ${iter} iteration bench for ${typeName} ${funcName}`);
  const before = Date.now();
  for(let i = 0; i < iter; i++) {
    func(...args)
  }
  const after = Date.now();
  console.log(`Finished ${iter} iterations of       ${typeName} ${funcName} in ${after - before} ms`);
  console.log('------------------------------------------------------------------');
}

async function main(args) {
  const secp256k1 = await instantiateSecp256k1();
  const secp = new pkg.TinySecp();
  console.log('------------------------------------------------------------------');
  for (const fixture of FIXTURES) {
    await performBench(eccNative[fixture.name], fixture.args, 'NATIVE         ', fixture.name, fixture.iterations);
    await performBench(ecc[fixture.name], fixture.args, 'JS             ', fixture.name, fixture.iterations);
    await performBench(fixture.bitcoinTSEquiv(secp256k1), fixture.args, 'BITCOIN-TS WASM', fixture.name, fixture.iterations);
    await performBench(secp[fixture.name].bind(secp), fixture.args, 'OUR-WASM       ', fixture.name, fixture.iterations);
  }
}

const FIXTURES = [
  {
    name: 'sign',
    iterations: 1000,
    args: [
      RANDOM_HASH,
      RANDOM_KEY,
    ],
    bitcoinTSEquiv: secp256k1 => secp256k1.signMessageHashCompact,
  },
];

main(process.argv.slice(2)).catch(err => {
  console.error(err)
  process.exit(err.code || 1)
})
