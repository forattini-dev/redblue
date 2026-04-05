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
const metrics = [
  ['lines', Number(linePct)],
  ['branches', Number(branchPct)],
  ['functions', Number(funcsPct)]
];

const failed = metrics.filter(([, value]) => value !== 100);

if (failed.length > 0) {
  for (const [name, value] of failed) {
    console.error(`SDK coverage below 100% for ${name}: ${value.toFixed(2)}%`);
  }
  process.exit(1);
}
