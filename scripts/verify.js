// Single-shot verification entrypoint used by the `verify` Compose service.
// Runs, in order:
//   1. decoding unit tests (node --test)
//   2. build check (node --check on every source file)
//   3. interface/HTTP smoke test against a freshly started real server
// Exits non-zero on the first failed stage.

import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decodeVcdiff } from '../src/vcdiff.js';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');

function run(cmd, args, label) {
  return new Promise((resolve) => {
    console.log(`\n=== [${label}] ${cmd} ${args.join(' ')}`);
    const child = spawn(cmd, args, { cwd: root, stdio: 'inherit' });
    child.on('exit', (code) => resolve(code ?? 1));
  });
}

async function waitForHealth(baseUrl, tries = 60) {
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetch(`${baseUrl}/healthz`);
      if (r.status === 200) return true;
    } catch {
      // server not up yet
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  return false;
}

async function smokeTest(baseUrl) {
  console.log(`\n=== [smoke] interface checks on ${baseUrl}`);
  let failures = 0;
  const expect = (cond, what) => {
    console.log(`${cond ? '  ok  ' : '  FAIL'} ${what}`);
    if (!cond) failures += 1;
  };

  const health = await fetch(`${baseUrl}/healthz`).then((r) => r.json());
  expect(health.status === 'ok', 'GET /healthz -> {"status":"ok"}');

  const page = await fetch(`${baseUrl}/`).then((r) => r.text());
  expect(page.includes('增量标定片'), 'GET / serves the workbench page');

  const samples = JSON.parse(readFileSync(join(root, 'fixtures', 'samples.json'), 'utf8'));

  // --- happy path: length + sha256 + per-window source ranges + evidence ---
  const okResp = await fetch(`${baseUrl}/api/decode`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      deltaBase64: samples.valid.deltaBase64,
      dictionaryBase64: samples.dictionaryBase64,
    }),
  });
  expect(okResp.status === 200, `valid sample HTTP 200 (got ${okResp.status})`);
  const ok = await okResp.json();
  expect(ok.ok === true, 'valid sample ok=true');
  expect(ok.length === samples.valid.expectedLength, `final length ${ok.length} == ${samples.valid.expectedLength}`);
  expect(ok.sha256 === samples.valid.expectedSha256, `sha256 ${ok.sha256}`);
  expect(ok.windows.length === samples.valid.expectedWindowCount, `window count ${ok.windows.length}`);
  const w2 = ok.windows[1];
  expect(w2.source.kind === 'TARGET' && w2.source.position === 5 && w2.source.length === 11,
    `window 2 source range TARGET [5,+11) (got ${w2.source.kind} [${w2.source.position},+${w2.source.length}))`);
  const copyModes = w2.instructions.filter((i) => i.op === 'COPY').map((i) => i.mode);
  expect(JSON.stringify(copyModes) === JSON.stringify(['SELF', 'NEAR0', 'SAME0']),
    `window 2 copy modes SELF/NEAR0/SAME0 (got ${copyModes})`);
  expect(w2.instructions.every((ins, idx) => ins.seq === idx), 'instructions listed in execution order');

  // --- failure path: first raw offset, no output ---------------------------
  const badResp = await fetch(`${baseUrl}/api/decode`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      deltaBase64: samples.badCopy.deltaBase64,
      dictionaryBase64: samples.dictionaryBase64,
    }),
  });
  expect(badResp.status === 400, `bad-copy sample HTTP 400 (got ${badResp.status})`);
  const bad = await badResp.json();
  expect(bad.ok === false && bad.error.code === 'COPY_NOT_GENERATED',
    `bad-copy code COPY_NOT_GENERATED (got ${bad.error?.code})`);
  expect(bad.error.offset === samples.badCopy.expectedOffset,
    `first raw offset ${bad.error.offset} == ${samples.badCopy.expectedOffset}`);
  expect(!('length' in bad) && !('windows' in bad), 'failure response retains no partial output');

  // --- non-minimal integer failure ------------------------------------------
  const nmResp = await fetch(`${baseUrl}/api/decode`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      deltaBase64: samples.nonMinimal.deltaBase64,
      dictionaryBase64: samples.dictionaryBase64,
    }),
  });
  const nm = await nmResp.json();
  expect(nmResp.status === 400 && nm.error.code === 'NON_MINIMAL_INTEGER',
    `non-minimal integer rejected at offset ${nm.error?.offset}`);

  // --- cross-window TARGET COPY: evidence split per producing window --------
  const cw = samples.crossWindow;
  const cwResp = await fetch(`${baseUrl}/api/decode`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      deltaBase64: cw.deltaBase64,
      dictionaryBase64: samples.dictionaryBase64,
    }),
  });
  expect(cwResp.status === 200, `cross-window sample HTTP 200 (got ${cwResp.status})`);
  const cwd = await cwResp.json();
  expect(cwd.ok === true, 'cross-window sample ok=true');
  expect(cwd.length === cw.expectedLength, `cross-window length ${cwd.length} == ${cw.expectedLength}`);
  expect(cwd.sha256 === cw.expectedSha256, `cross-window sha256 ${cwd.sha256}`);
  expect(cwd.windows.length === cw.expectedWindowCount,
    `cross-window window count ${cwd.windows.length} == ${cw.expectedWindowCount}`);

  const cwWin = cwd.windows[cw.crossingCopy.windowIndex];
  expect(!!cwWin && cwWin.source.kind === 'TARGET',
    `cross-window window ${cw.crossingCopy.windowIndex + 1} is a TARGET window`);
  const crossing = cwWin?.instructions.find((i) =>
    i.op === 'COPY' && i.seq === cw.crossingCopy.seq);
  expect(!!crossing, 'crossing COPY present in instruction evidence');
  if (crossing) {
    expect(crossing.size === cw.crossingCopy.size,
      `crossing COPY size ${crossing.size} == ${cw.crossingCopy.size}`);
    expect(crossing.crossesWindows === true, 'crossing COPY flagged crossesWindows=true');
    expect(Array.isArray(crossing.ranges) && crossing.ranges.length === 2,
      `crossing COPY reports two segments (got ${crossing.ranges?.length})`);
    for (let i = 0; i < cw.crossingCopy.segments.length; i++) {
      const got = crossing.ranges[i];
      const want = cw.crossingCopy.segments[i];
      expect(!!got && got.area === 'PRIOR_TARGET' &&
        got.start === want.start && got.end === want.end &&
        got.producerWindow === want.producerWindow,
        `crossing segment ${i + 1}: window #${want.producerWindow} [${want.start},${want.end}) ` +
          `(got ${got ? JSON.stringify([got.area, got.start, got.end, got.producerWindow]) : 'none'})`);
    }
    // Segments are contiguous and cover the full COPY.
    const contiguous = crossing.ranges[0].end === crossing.ranges[1].start;
    const total = crossing.ranges.reduce((n, s) => n + (s.end - s.start), 0);
    expect(contiguous && total === crossing.size,
      `segments contiguous and cover all ${crossing.size} bytes (covered ${total})`);
    expect(crossing.range.producerWindow === null,
      'aggregate range is not attributed to a single producing window');

    // Audit basis recomputed end-to-end: decode the same payload locally, then
    // read the byte intervals the HTTP evidence named. Their concatenation
    // must equal exactly the bytes this COPY placed into window 3's output.
    const local = decodeVcdiff(
      Buffer.from(cw.deltaBase64, 'base64'),
      Buffer.from(samples.dictionaryBase64, 'base64'),
    );
    const winOutStart = cwWin.targetOffset;
    const recomputed = Buffer.concat(crossing.ranges.map((s) =>
      Buffer.from(local.output.subarray(s.start, s.end))));
    // The crossing COPY is window 3's first instruction, hence its produced
    // bytes are exactly the first `size` bytes of window 3's output.
    const producedSlice = Buffer.from(
      local.output.subarray(winOutStart, winOutStart + crossing.size));
    expect(recomputed.equals(producedSlice) &&
      recomputed.toString('hex') === cw.crossingCopy.producedHex,
      `bytes at reported ranges reproduce the COPY output ${cw.crossingCopy.producedHex} ` +
        `(got ${recomputed.toString('hex')})`);
  }

  // The ordinary single-window TARGET COPY in the same stream is unaffected.
  const single = cwWin?.instructions.find((i) =>
    i.op === 'COPY' && i.seq === cw.singleCopy.seq);
  expect(!!single && single.crossesWindows === false &&
    Array.isArray(single.ranges) && single.ranges.length === 1 &&
    single.ranges[0].producerWindow === cw.singleCopy.producerWindow &&
    single.ranges[0].start === cw.singleCopy.start &&
    single.ranges[0].end === cw.singleCopy.end &&
    single.range.producerWindow === cw.singleCopy.producerWindow,
    `ordinary TARGET COPY keeps single-segment evidence (window #${cw.singleCopy.producerWindow} ` +
      `[${cw.singleCopy.start},${cw.singleCopy.end}))`);

  // Every ordinary COPY on the original two-window sample still reports a
  // single range identical to ranges[0] (no regression for dict/SOURCE copies).
  expect(ok.windows.every((w) => w.instructions
    .filter((i) => i.op === 'COPY')
    .every((i) => Array.isArray(i.ranges) && i.ranges.length === 1 &&
      i.crossesWindows === false &&
      i.range.area === i.ranges[0].area &&
      i.range.start === i.ranges[0].start &&
      i.range.end === i.ranges[0].end &&
      i.range.producerWindow === i.ranges[0].producerWindow)),
  'existing sample: all COPY evidence stays single-segment and unchanged');

  // --- dictionary-less stream with a crossing TARGET COPY -------------------
  const nd = samples.noDict;
  const ndResp = await fetch(`${baseUrl}/api/decode`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ deltaBase64: nd.deltaBase64, dictionaryBase64: '' }),
  });
  expect(ndResp.status === 200, `no-dictionary sample HTTP 200 (got ${ndResp.status})`);
  const ndd = await ndResp.json();
  expect(ndd.ok === true && ndd.length === nd.expectedLength &&
    ndd.sha256 === nd.expectedSha256 && ndd.windows.length === nd.expectedWindowCount,
    `no-dictionary sample length ${ndd.length}/sha/windows`);
  const ndCopy = ndd.windows[2].instructions.find((i) => i.op === 'COPY');
  const ndSegs = nd.crossingSegments;
  expect(!!ndCopy && ndCopy.crossesWindows === true && ndCopy.ranges.length === 2 &&
    ndCopy.ranges.every((s, i) =>
      s.producerWindow === ndSegs[i][0] && s.start === ndSegs[i][1] && s.end === ndSegs[i][2]),
  'no-dictionary crossing COPY split into windows #0 [2,4) and #1 [4,6)');

  // --- malformed base64 ------------------------------------------------------
  const b64Resp = await fetch(`${baseUrl}/api/decode`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ deltaBase64: 'not-base64!!' }),
  });
  expect((await b64Resp.json()).error.code === 'BAD_BASE64', 'malformed Base64 rejected');

  // --- reset endpoint --------------------------------------------------------
  const resetResp = await fetch(`${baseUrl}/api/reset`, { method: 'POST' });
  expect(resetResp.status === 200, 'POST /api/reset -> 200');

  return failures === 0;
}

async function main() {
  // In Compose, SMOKE_BASE_URL points at the running "web" service.
  // Standalone: a fresh local server is started on SMOKE_PORT.
  const externalBase = process.env.SMOKE_BASE_URL;
  const port = process.env.SMOKE_PORT ?? '18080';
  const localBase = `http://127.0.0.1:${port}`;

  const testCode = await run(process.execPath, ['--test', 'test/'], 'unit tests');
  if (testCode !== 0) {
    console.error('\nVERIFY FAILED: unit tests');
    process.exit(1);
  }

  const checkCode = await run(process.execPath, ['scripts/check-syntax.js'], 'build check');
  if (checkCode !== 0) {
    console.error('\nVERIFY FAILED: build check');
    process.exit(1);
  }

  let baseUrl = externalBase;
  let server = null;

  if (!baseUrl) {
    console.log(`\n=== [smoke] starting local server on port ${port}`);
    server = spawn(process.execPath, ['src/server.js'], {
      cwd: root,
      stdio: ['ignore', 'pipe', 'inherit'],
      env: { ...process.env, HOST: '127.0.0.1', PORT: String(port) },
    });
    server.stdout.on('data', (d) => process.stdout.write(`[server] ${d}`));
    baseUrl = localBase;
  }

  let ok = false;
  try {
    if (!(await waitForHealth(baseUrl))) {
      console.error(`server at ${baseUrl} did not become healthy in time`);
    } else {
      ok = await smokeTest(baseUrl);
    }
  } finally {
    if (server) {
      server.kill('SIGTERM');
      await new Promise((r) => server.on('exit', r));
    }
  }

  if (ok) {
    console.log('\nVERIFY PASSED: unit tests + build check + HTTP smoke all green');
    process.exit(0);
  }
  console.error('\nVERIFY FAILED: HTTP smoke');
  process.exit(1);
}

main().catch((err) => {
  console.error('VERIFY ERRORED:', err);
  process.exit(1);
});
