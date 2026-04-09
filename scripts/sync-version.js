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

  // Sync Cargo.toml to match VERSION file.
  // package.json is the source of truth (set by pnpm version or CI workflow)
  // — never overwrite it here. The "version" hook in package.json handles
  // syncing package.json → VERSION + Cargo.toml at bump time.
  syncCargoToml(version);

  // Only sync package.json if it has a LOWER version (prevents downgrade)
  const currentPkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
  const pkgVersion = currentPkg.version || '';
  if (!pkgVersion || (!pkgVersion.includes('-') && pkgVersion < version)) {
    syncPackageJson(version);
  }

  process.stdout.write(`Synced version ${version} (pkg: ${pkgVersion})\n`);
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exit(1);
}
