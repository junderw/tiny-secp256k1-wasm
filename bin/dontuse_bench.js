const pkg = require('../pkg');
const ecc = require('tiny-secp256k1/js');
const eccNative = require('tiny-secp256k1/native');
const bitcoinTS = require('bitcoin-ts');
const { instantiateSecp256k1 } = bitcoinTS;
const crypto = require('crypto');

const readline = require('readline');
const cursorTo = x =>
  new Promise(r => {
    process.stdout.clearLine();
    readline.cursorTo(process.stdout, x, undefined, () => {
      r();
    });
  });

const RANDOM_KEY = crypto.randomBytes(32);
RANDOM_KEY[0] &= 0x7f;
RANDOM_KEY[31] = 0xff; // (lazy) make sure it's not invalid
const RANDOM_KEY2 = crypto.randomBytes(32);
RANDOM_KEY2[0] = 0x00;
RANDOM_KEY2[1] = 0x00;
RANDOM_KEY2[2] = 0x00; // make it smaller than 1
RANDOM_KEY2[31] = 0xff;

const RANDOM_HASH = crypto.randomBytes(32);

const PUBKEY_C = eccNative.pointFromScalar(RANDOM_KEY, true);
const PUBKEY_UC = eccNative.pointCompress(PUBKEY_C, false);
const PUBKEY_C2 = eccNative.pointFromScalar(RANDOM_KEY2, true);
const PUBKEY_UC2 = eccNative.pointCompress(PUBKEY_C2, false);

const SIG = eccNative.sign(RANDOM_HASH, RANDOM_KEY);

async function performBench(func, fixture, typeName) {
  const { name: funcName, iterations: iter, args, notes } = fixture;
  process.stdout.write(
    `Starting ${iter} iteration bench for ${typeName} ${funcName}${notes}`,
  );
  const before = Date.now();
  for (let i = 0; i < iter; i++) {
    func(...args);
  }
  const after = Date.now();
  const diffTime = after - before;
  await cursorTo(0);
  console.log(
    `Finished ${iter} iterations of       ${typeName} ${funcName}${notes} in ${diffTime} ms`,
  );
  return diffTime;
}

async function main(args) {
  const secp256k1 = await instantiateSecp256k1();
  const secp = new pkg.TinySecp();
  const slowerNames = [];
  console.log(
    '------------------------------------------------------------------',
  );
  for (const fixture of FIXTURES) {
    console.log(`     Fixture: ${fixture.name}${fixture.notes}`);
    console.log(
      '------------------------------------------------------------------',
    );
    const nativeT = await performBench(
      eccNative[fixture.name],
      fixture,
      'NATIVE         ',
    );
    const javaScT = await performBench(
      ecc[fixture.name],
      fixture,
      'JS             ',
    );
    const rsWasmT = await performBench(
      secp[fixture.name].bind(secp),
      fixture,
      'OUR-WASM       ',
    );
    let bitcTST;
    if (fixture.bitcoinTSEquiv) {
      bitcTST = await performBench(
        fixture.bitcoinTSEquiv(secp256k1),
        fixture,
        'BITCOIN-TS WASM',
      );
    }
    console.log(
      '------------------------------------------------------------------',
    );
    if (javaScT < rsWasmT) {
      console.log(
        '************ ^^^^^ OUR WASM IS SLOWER THAN JS ********************',
      );
      console.log(
        '------------------------------------------------------------------',
      );
      slowerNames.push(`- ${fixture.name}${fixture.notes}`);
    }
  }
  if (slowerNames.length > 0) {
    console.log(
      '************ vvvvv OUR WASM IS SLOWER THAN JS ********************',
    );
    console.log(
      '------------------------------------------------------------------',
    );
    console.log(slowerNames.join('\n'));
  }
}

const FIXTURES = [
  {
    name: 'isPoint',
    notes: '',
    iterations: 10000,
    args: [PUBKEY_C],
    bitcoinTSEquiv: null, // has none
  },
  {
    name: 'isPointCompressed',
    notes: '',
    iterations: 10000,
    args: [PUBKEY_C],
    bitcoinTSEquiv: null,
  },
  {
    name: 'isPoint',
    notes: ' with uncompressed pubkey',
    iterations: 1000000,
    args: [PUBKEY_UC],
    bitcoinTSEquiv: null,
  },
  {
    name: 'isPointCompressed',
    notes: ' with uncompressed pubkey',
    iterations: 1000000,
    args: [PUBKEY_UC],
    bitcoinTSEquiv: null,
  },
  {
    name: 'isPrivate',
    notes: '',
    iterations: 1000000,
    args: [RANDOM_KEY],
    bitcoinTSEquiv: secp256k1 => secp256k1.validatePrivateKey,
  },
  {
    name: 'pointAdd',
    notes: '',
    iterations: 1000,
    args: [PUBKEY_C, PUBKEY_C2, true],
    bitcoinTSEquiv: null,
  },
  {
    name: 'pointAddScalar',
    notes: '',
    iterations: 1000,
    args: [PUBKEY_C, RANDOM_KEY2, true],
    bitcoinTSEquiv: secp256k1 => secp256k1.addTweakPublicKeyCompressed,
  },
  {
    name: 'pointCompress',
    notes: '',
    iterations: 100000,
    args: [PUBKEY_UC, true],
    bitcoinTSEquiv: secp256k1 => secp256k1.compressPublicKey,
  },
  {
    name: 'pointFromScalar',
    notes: '',
    iterations: 1000,
    args: [RANDOM_KEY, true],
    bitcoinTSEquiv: secp256k1 => secp256k1.derivePublicKeyCompressed,
  },
  {
    name: 'pointMultiply',
    notes: '',
    iterations: 1000,
    args: [PUBKEY_C, RANDOM_KEY, true],
    bitcoinTSEquiv: secp256k1 => secp256k1.mulTweakPublicKeyCompressed,
  },
  {
    name: 'privateAdd',
    notes: '',
    iterations: 100000,
    args: [RANDOM_KEY, RANDOM_KEY2],
    bitcoinTSEquiv: secp256k1 => secp256k1.addTweakPrivateKey,
  },
  {
    name: 'privateSub',
    notes: '',
    iterations: 100000,
    args: [RANDOM_KEY, RANDOM_KEY2],
    bitcoinTSEquiv: null,
  },
  {
    name: 'sign',
    notes: '',
    iterations: 1000,
    args: [RANDOM_HASH, RANDOM_KEY],
    bitcoinTSEquiv: secp256k1 => secp256k1.signMessageHashCompact,
  },
  {
    name: 'signWithEntropy',
    notes: '',
    iterations: 1000,
    args: [RANDOM_HASH, RANDOM_KEY, RANDOM_KEY2],
    bitcoinTSEquiv: null,
  },
  {
    name: 'verify',
    notes: '',
    iterations: 1000,
    args: [RANDOM_HASH, PUBKEY_C, SIG],
    bitcoinTSEquiv: secp256k1 => (hash, pub, sig, strict) => {
      if (strict) return secp256k1.verifySignatureCompactLowS(sig, pub, hash);
      else return secp256k1.verifySignatureCompact(sig, pub, hash);
    },
  },
];

main(process.argv.slice(2)).catch(err => {
  console.error(err);
  process.exit(err.code || 1);
});
