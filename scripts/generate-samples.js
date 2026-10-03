// Generates deterministic verification samples:
//   valid      - two windows; window 2 uses a VCD_TARGET source segment that
//                references window 1 output, plus NEAR and SAME cache copies
//   badCopy    - same stream but window 2 copies target bytes not yet generated
//   nonMinimal - stream containing a non-shortest integer encoding
//   truncated  - a valid stream cut off mid-window
//
// Outputs fixtures/samples.json (base64 payloads + expected facts) and prints
// a short report.

import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decodeVcdiff } from '../src/vcdiff.js';
import { WindowEncoder, assemble } from '../test/helpers/encoder.js';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');

const encoder = new TextEncoder();
const b64 = (u8) => Buffer.from(u8).toString('base64');
const sha256 = (u8) => createHash('sha256').update(u8).digest('hex');

const dictionary = encoder.encode('0123456789-HELLO-DICT'); // 20 bytes

// ---- Window 1: SOURCE window against the dictionary -----------------------
function buildWindow1() {
  const w = new WindowEncoder('SOURCE', 0, dictionary.length);
  w.copy(0, 11);          // "0123456789-"  (SELF)
  w.add(encoder.encode('WORLD'));
  w.copy(11, 4);          // "HELL"         (SELF)
  w.run(0x21, 4);         // '!' x4
  return w;
}

// ---- Window 2: TARGET window sourced from window 1 output -----------------
function buildWindow2() {
  // Prior-target segment: output[5:16] == "56789-WORLD" (s = 11)
  const w = new WindowEncoder('TARGET', 5, 11);
  w.copy(5, 5);                        // "-WORL", SELF; primes near/same[5]
  w.copy(10, 1);                       // "D", encoder picks NEAR0 (10 - 5 = 5)
  w.add(encoder.encode('>>'));
  w.copy(5, 5, { mode: 6 });           // "-WORL", SAME0 byte 5 -> same[5] == 5
  return w;
}

// ---- Window 2 (bad): copies bytes that have not been generated yet --------
function buildBadWindow2() {
  const w = new WindowEncoder('TARGET', 5, 11);
  w.add(encoder.encode('XY'));         // here == 13
  w.copy(13, 4, { mode: 1 });          // HERE encoded 0 -> addr == 13: future
  return w;
}

// ---- Three-window stream whose TARGET COPY crosses an earlier-window seam
//   window 0: SOURCE -> "0123456789-WORLD"  output [0, 16)
//   window 1: NONE   -> "ABCDEFGH"          output [16, 24)
//   window 2: TARGET source segment output[13,24) = "WORLDABCDEFGH" (s = 11)
// The first COPY at U address 2 reads output[15:21]: one byte ("D") produced
// by window 0 followed by five bytes ("ABCDE") produced by window 1.
function buildCrossWindowStream() {
  const w1 = new WindowEncoder('SOURCE', 0, dictionary.length);
  w1.copy(0, 11);
  w1.add(encoder.encode('WORLD'));

  const w2 = new WindowEncoder('NONE');
  w2.add(encoder.encode('ABCDEFGH'));

  const w3 = new WindowEncoder('TARGET', 13, 11);
  w3.copy(2, 6);  // crosses the window-0/window-1 boundary at output[16]
  w3.copy(8, 3);  // "FGH", entirely inside window 1
  w3.add(encoder.encode('!!'));

  return {
    delta: assemble(w1.build(), w2.build(), w3.build()),
    expectedOutput: encoder.encode('0123456789-WORLDABCDEFGHDABCDEFGH!!'),
  };
}

// ---- Dictionary-less stream: a TARGET COPY crossing an earlier-window seam
function buildNoDictStream() {
  const w1 = new WindowEncoder('NONE');
  w1.add(encoder.encode('AAAA'));          // output [0, 4)
  const w2 = new WindowEncoder('NONE');
  w2.add(encoder.encode('BBBB'));          // output [4, 8)
  const w3 = new WindowEncoder('TARGET', 2, 4); // segment output[2:6] = "AABB"
  w3.copy(0, 4);                           // "AA" (window 0) + "BB" (window 1)
  return {
    delta: assemble(w1.build(), w2.build(), w3.build()),
    expectedOutput: encoder.encode('AAAABBBBAABB'),
  };
}

const w1 = buildWindow1();
const w2 = buildWindow2();
const validDelta = assemble(w1.build(), w2.build());

const badW2 = buildBadWindow2();
const badCopyDelta = assemble(w1.build(), badW2.build());

const nonMinimalW1 = buildWindow1();
// Force the RUN size integer in window 1 to carry a leading zero group.
const nonMinimalDelta = assemble(nonMinimalW1.build());
// Rebuild with the flag instead of post-editing, to keep lengths consistent:
function buildNonMinimal() {
  const w = new WindowEncoder('SOURCE', 0, dictionary.length);
  w.copy(0, 11);
  w.add(encoder.encode('WORLD'));
  w.copy(11, 4);
  w.run(0x21, 4, { nonMinimalSize: true });
  return assemble(w.build());
}
const nonMinimalDeltaFixed = buildNonMinimal();

const truncatedDelta = validDelta.subarray(0, validDelta.length - 3);

const crossWindow = buildCrossWindowStream();
const crossResult = decodeVcdiff(crossWindow.delta, dictionary);

const noDict = buildNoDictStream();
const noDictResult = decodeVcdiff(noDict.delta, new Uint8Array(0));

// ---- Decode and verify every expectation ----------------------------------
const validResult = decodeVcdiff(validDelta, dictionary);
const expectedOutput = encoder.encode('0123456789-WORLDHELL!!!!' + '-WORLD>>-WORL');

if (
  validResult.length !== expectedOutput.length ||
  !validResult.output.every((b, i) => b === expectedOutput[i])
) {
  throw new Error('valid sample mismatch');
}

let badError = null;
try {
  decodeVcdiff(badCopyDelta, dictionary);
} catch (err) {
  badError = err;
}
if (!badError || badError.code !== 'COPY_NOT_GENERATED' || typeof badError.offset !== 'number') {
  throw new Error(`expected COPY_NOT_GENERATED with offset, got ${badError}`);
}

let nmError = null;
try {
  decodeVcdiff(nonMinimalDeltaFixed, dictionary);
} catch (err) {
  nmError = err;
}
if (!nmError || nmError.code !== 'NON_MINIMAL_INTEGER' || typeof nmError.offset !== 'number') {
  throw new Error(`expected NON_MINIMAL_INTEGER with offset, got ${nmError}`);
}

let truncError = null;
try {
  decodeVcdiff(truncatedDelta, dictionary);
} catch (err) {
  truncError = err;
}
if (!truncError || truncError.code !== 'TRUNCATED') {
  throw new Error(`expected TRUNCATED, got ${truncError}`);
}

// ---- Cross-window evidence must split the COPY by producing window --------
if (
  crossResult.length !== crossWindow.expectedOutput.length ||
  !crossResult.output.every((b, i) => b === crossWindow.expectedOutput[i])
) {
  throw new Error('cross-window sample output mismatch');
}
const crossCopy = crossResult.windows[2].instructions.filter((i) => i.op === 'COPY')[0];
if (
  crossCopy.size !== 6 ||
  crossCopy.crossesWindows !== true ||
  crossCopy.ranges.length !== 2 ||
  crossCopy.ranges[0].start !== 15 || crossCopy.ranges[0].end !== 16 ||
  crossCopy.ranges[0].producerWindow !== 0 ||
  crossCopy.ranges[1].start !== 16 || crossCopy.ranges[1].end !== 21 ||
  crossCopy.ranges[1].producerWindow !== 1 ||
  crossCopy.range.producerWindow !== null
) {
  throw new Error(`cross-window sample evidence mismatch: ${JSON.stringify(crossCopy)}`);
}

// ---- Dictionary-less sample decodes with an empty dictionary --------------
if (
  noDictResult.length !== noDict.expectedOutput.length ||
  !noDictResult.output.every((b, i) => b === noDict.expectedOutput[i])
) {
  throw new Error('no-dictionary sample output mismatch');
}

// Also prove a corrupted dictionary rejects the source range.
let rangeError = null;
try {
  decodeVcdiff(validDelta, dictionary.subarray(0, 10));
} catch (err) {
  rangeError = err;
}
if (!rangeError || rangeError.code !== 'SOURCE_RANGE') {
  throw new Error(`expected SOURCE_RANGE, got ${rangeError}`);
}

const sample = {
  generatedAt: new Date().toISOString(),
  dictionaryBase64: b64(dictionary),
  valid: {
    deltaBase64: b64(validDelta),
    expectedLength: validResult.length,
    expectedSha256: sha256(validResult.output),
    expectedWindowCount: validResult.windows.length,
  },
  badCopy: {
    deltaBase64: b64(badCopyDelta),
    expectedCode: 'COPY_NOT_GENERATED',
    expectedOffset: badError.offset,
  },
  nonMinimal: {
    deltaBase64: b64(nonMinimalDeltaFixed),
    expectedCode: 'NON_MINIMAL_INTEGER',
    expectedOffset: nmError.offset,
  },
  truncated: {
    deltaBase64: b64(truncatedDelta),
    expectedCode: 'TRUNCATED',
  },
  crossWindow: {
    deltaBase64: b64(crossWindow.delta),
    expectedLength: crossResult.length,
    expectedSha256: sha256(crossResult.output),
    expectedWindowCount: crossResult.windows.length,
    // The crossing COPY (window 3, first instruction) and its per-window
    // evidence segments; bytes hex re-assembled from the segments must equal
    // the bytes the COPY actually produced.
    crossingCopy: {
      windowIndex: 2,
      seq: 0,
      size: 6,
      producedHex: Buffer.from(encoder.encode('DABCDE')).toString('hex'),
      segments: crossCopy.ranges.map((s) => ({
        start: s.start,
        end: s.end,
        producerWindow: s.producerWindow,
      })),
    },
    // Second COPY lives entirely inside window 1's output.
    singleCopy: {
      seq: 1,
      start: 21,
      end: 24,
      producerWindow: 1,
    },
  },
  noDict: {
    deltaBase64: b64(noDict.delta),
    expectedLength: noDictResult.length,
    expectedSha256: sha256(noDictResult.output),
    expectedWindowCount: noDictResult.windows.length,
    crossingSegments: [[0, 2, 4], [1, 4, 6]],
  },
};

const outDir = join(root, 'fixtures');
mkdirSync(outDir, { recursive: true });
writeFileSync(join(outDir, 'samples.json'), JSON.stringify(sample, null, 2) + '\n');

console.log('samples written to fixtures/samples.json');
console.log(`  valid      : ${validResult.length} bytes, ${validResult.windows.length} windows, sha256 ${sample.valid.expectedSha256}`);
console.log(`  badCopy    : ${badError.code} at raw offset ${badError.offset}`);
console.log(`  nonMinimal : ${nmError.code} at raw offset ${nmError.offset}`);
console.log(`  truncated  : ${truncError.code}`);
