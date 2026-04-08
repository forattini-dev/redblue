#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const rootDir = path.join(__dirname, '..');
const versionPath = path.join(rootDir, 'VERSION');
const cargoTomlPath = path.join(rootDir, 'Cargo.toml');
const packageJsonPath = path.join(rootDir, 'package.json');

const args = process.argv.slice(2);
const setIndex = args.indexOf('--set');

function readVersion() {
  return fs.readFileSync(versionPath, 'utf8').trim();
}

function validateVersion(version) {
  if (!/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(version)) {
    throw new Error(`invalid version: ${version}`);
  }
}

function writeVersion(version) {
  fs.writeFileSync(versionPath, `${version}\n`, 'utf8');
}

function syncCargoToml(version) {
  const cargoToml = fs.readFileSync(cargoTomlPath, 'utf8');
  const currentMatch = cargoToml.match(/^version\s*=\s*"([^"]+)"$/m);
  if (!currentMatch) {
    throw new Error('failed to find Cargo.toml version');
  }
  if (currentMatch[1] === version) {
    return;
  }

  const next = cargoToml.replace(
    /^version\s*=\s*"[^"]+"$/m,
    `version = "${version}"`
  );

  fs.writeFileSync(cargoTomlPath, next, 'utf8');
}

function syncPackageJson(version) {
  const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
  if (packageJson.version === version) {
    return;
  }
  packageJson.version = version;
  fs.writeFileSync(packageJsonPath, `${JSON.stringify(packageJson, null, 2)}\n`, 'utf8');
}

try {
  let version = readVersion();

  if (setIndex !== -1) {
    version = args[setIndex + 1];
    if (!version) {
      throw new Error('missing value after --set');
    }
    validateVersion(version);
    writeVersion(version);
  } else {
    validateVersion(version);
  }

  // If package.json already has a prerelease version (e.g. 0.2.2-next.48,
  // set by the CI release workflow), don't overwrite it with the base version.
  // This prevents "npm publish" from trying to republish an existing stable version.
  const currentPkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
  if (currentPkg.version && currentPkg.version.includes('-') && !version.includes('-')) {
    process.stdout.write(`Synced version ${version} (kept package.json at ${currentPkg.version})\n`);
    syncCargoToml(version);
  } else {
    syncCargoToml(version);
    syncPackageJson(version);
    process.stdout.write(`Synced version ${version}\n`);
  }
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exit(1);
}
