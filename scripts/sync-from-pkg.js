#!/usr/bin/env node
// Runs as the npm/pnpm "version" lifecycle hook.
//
// Flow:
//   pnpm version patch
//     1. pnpm bumps package.json (e.g. 0.2.6 → 0.2.7)
//     2. pnpm runs this "version" script
//     3. We update VERSION and Cargo.toml to match package.json
//     4. We stage the changed files so pnpm includes them in the tag commit
//     5. pnpm commits + creates the git tag
//
// After this, `git push --follow-tags` triggers the release workflow.
'use strict';

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const rootDir = path.join(__dirname, '..');
const versionPath = path.join(rootDir, 'VERSION');
const cargoTomlPath = path.join(rootDir, 'Cargo.toml');
const packageJsonPath = path.join(rootDir, 'package.json');

const pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
const version = pkg.version;

if (!version || !/^\d+\.\d+\.\d+/.test(version)) {
  console.error(`Invalid version in package.json: ${version}`);
  process.exit(1);
}

// Strip any prerelease/build suffix for Cargo.toml (semver only allows X.Y.Z)
const cargoVersion = version.replace(/[-+].*$/, '');

// Update VERSION file
fs.writeFileSync(versionPath, `${cargoVersion}\n`, 'utf8');

// Update Cargo.toml
const cargoToml = fs.readFileSync(cargoTomlPath, 'utf8');
const updated = cargoToml.replace(
  /^version\s*=\s*"[^"]+"/m,
  `version = "${cargoVersion}"`
);
if (updated !== cargoToml) {
  fs.writeFileSync(cargoTomlPath, updated, 'utf8');
}

// Regenerate Cargo.lock to match the new Cargo.toml version
// (CI uses --locked which requires Cargo.lock in sync)
try {
  execSync('cargo check --quiet', { cwd: rootDir, stdio: 'inherit', timeout: 120000 });
} catch (_) {
  // cargo check may fail for other reasons; Cargo.lock is still updated
}

// Stage the files so they're included in pnpm's version commit
execSync('git add VERSION Cargo.toml Cargo.lock', { cwd: rootDir, stdio: 'inherit' });

console.log(`Synced VERSION + Cargo.toml to ${cargoVersion}`);
