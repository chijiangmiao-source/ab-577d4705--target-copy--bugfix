// Generates deterministic verification samples:
//   valid       - two windows; window 2 uses a VCD_TARGET source segment that
//                 references window 1 output, plus NEAR and SAME cache copies
//   badCopy     - same stream but window 2 copies target bytes not yet generated
//   nonMinimal  - stream containing a non-shortest integer encoding
//   truncated   - a valid stream cut off mid-window
//   crossWindow - three windows; the final window's first TARGET COPY straddles
//                 two earlier windows and must carry per-window provenance
//   noDict      - single window with no dictionary and no source segment
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

// ---- Three-window stream whose final TARGET COPY straddles two history ----
// windows, proving per-segment provenance.
function buildCrossWindow() {
  // Window 0 emits output[0:10]  = "0123456789" from the dictionary.
  const a = new WindowEncoder('SOURCE', 0, dictionary.length);
  a.copy(0, 10);
  // Window 1 emits output[10:20] = "ABCDEFGHIJ" with no source segment.
  const b = new WindowEncoder('NONE');
  b.add(encoder.encode('ABCDEFGHIJ'));
  // Window 2's TARGET source segment is output[5:15] = "56789ABCDE".
  const c = new WindowEncoder('TARGET', 5, 10);
  c.copy(0, 10); // "56789ABCDE": reads across the window0/window1 boundary
  c.copy(5, 5);  // "ABCDE": wholly inside window 1's output
  return { a, b, c };
}

// ---- Stream with no dictionary and no source segment at all ----------------
function buildNoDict() {
  const w = new WindowEncoder('NONE');
  w.add(encoder.encode('NO-DICTIONARY'));
  w.run(0x2a, 3); // "***"
  return w;
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

// ---- Cross-window sample ---------------------------------------------------
const cross = buildCrossWindow();
const crossDelta = assemble(cross.a.build(), cross.b.build(), cross.c.build());
const crossResult = decodeVcdiff(crossDelta, dictionary);
const crossExpected = encoder.encode('0123456789ABCDEFGHIJ56789ABCDEABCDE');
if (
  crossResult.length !== crossExpected.length ||
  !crossResult.output.every((b, i) => b === crossExpected[i])
) {
  throw new Error('cross-window sample mismatch');
}
if (crossResult.windows.length !== 3) {
  throw new Error(`cross-window sample expected 3 windows, got ${crossResult.windows.length}`);
}
const crossCopies = crossResult.windows[2].instructions;
const straddle = crossCopies[0];
if (straddle.ranges.length !== 2) {
  throw new Error(`straddling COPY expected 2 provenance segments, got ${straddle.ranges.length}`);
}
const [seg0, seg1] = straddle.ranges;
if (
  seg0.area !== 'PRIOR_TARGET' || seg0.start !== 5 || seg0.end !== 10 || seg0.producerWindow !== 0 ||
  seg1.area !== 'PRIOR_TARGET' || seg1.start !== 10 || seg1.end !== 15 || seg1.producerWindow !== 1
) {
  throw new Error(`straddling COPY segments wrong: ${JSON.stringify(straddle.ranges)}`);
}
const inside = crossCopies[1];
if (
  inside.ranges.length !== 1 ||
  inside.ranges[0].start !== 10 || inside.ranges[0].end !== 15 ||
  inside.ranges[0].producerWindow !== 1
) {
  throw new Error(`single-window COPY segment wrong: ${JSON.stringify(inside.ranges)}`);
}

// ---- No-dictionary sample --------------------------------------------------
const noDict = buildNoDict();
const noDictDelta = assemble(noDict.build());
const noDictResult = decodeVcdiff(noDictDelta, new Uint8Array(0));
const noDictExpected = encoder.encode('NO-DICTIONARY***');
if (
  noDictResult.length !== noDictExpected.length ||
  !noDictResult.output.every((b, i) => b === noDictExpected[i])
) {
  throw new Error('no-dictionary sample mismatch');
}

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
    deltaBase64: b64(crossDelta),
    expectedLength: crossResult.length,
    expectedSha256: sha256(crossResult.output),
    expectedWindowCount: 3,
    // The first COPY in the final window reads across the window0/window1
    // boundary; evidence must list both segments in read order.
    straddle: {
      producerWindows: [0, 1],
      ranges: [
        { area: 'PRIOR_TARGET', start: 5, end: 10 },
        { area: 'PRIOR_TARGET', start: 10, end: 15 },
      ],
    },
    // The following COPY stays inside one history window (window 1).
    single: {
      producerWindow: 1,
      start: 10,
      end: 15,
    },
  },
  noDict: {
    deltaBase64: b64(noDictDelta),
    expectedLength: noDictResult.length,
    expectedSha256: sha256(noDictResult.output),
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
console.log(`  crossWindow: ${crossResult.length} bytes, 3 windows, straddling COPY -> 2 segments`);
console.log(`  noDict     : ${noDictResult.length} bytes, ${noDictResult.windows.length} window`);
