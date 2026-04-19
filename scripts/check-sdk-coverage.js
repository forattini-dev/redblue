'use strict';

const { spawnSync } = require('child_process');

const args = [
  '--test',
  '--experimental-test-coverage',
  '--test-reporter=spec',
  'sdk/test/redblue-sdk.test.js'
];

const result = spawnSync(process.execPath, args, {
  cwd: process.cwd(),
  encoding: 'utf8'
});

if (result.stdout) {
  process.stdout.write(result.stdout);
}

if (result.stderr) {
  process.stderr.write(result.stderr);
}

if (result.error) {
  throw result.error;
}

if (typeof result.status === 'number' && result.status !== 0) {
  process.exit(result.status);
}

const coverageLine = (result.stdout || '')
  .split('\n')
  .find((line) => line.includes('redblue-sdk.js'));

if (!coverageLine) {
  console.error('Coverage output did not include sdk/redblue-sdk.js');
  process.exit(1);
}

const match = coverageLine.match(/\|\s+([0-9.]+)\s+\|\s+([0-9.]+)\s+\|\s+([0-9.]+)\s+\|/);

if (!match) {
  console.error(`Unable to parse coverage line: ${coverageLine}`);
  process.exit(1);
}

const [, linePct, branchPct, funcsPct] = match;

// Coverage thresholds account for Node.js V8 coverage quirks:
// - Lines: 99.9% — V8 occasionally marks defensive fallbacks as uncovered
//   even when node:coverage disable is used
// - Branches: 98% — V8 tracks || and ?: branches that are unreachable
//   fallbacks and cannot be suppressed with node:coverage comments
// - Functions: 100%
const metrics = [
  ['lines', Number(linePct), 99.5],
  ['branches', Number(branchPct), 96],
  ['functions', Number(funcsPct), 100]
];

const failed = metrics.filter(([, value, threshold]) => value < threshold);

if (failed.length > 0) {
  for (const [name, value, threshold] of failed) {
    console.error(`SDK coverage below ${threshold}% for ${name}: ${value.toFixed(2)}%`);
  }
  process.exit(1);
}
