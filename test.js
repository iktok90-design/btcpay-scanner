'use strict';

const fs = require('fs');
const path = require('path');

// Verify all required files exist
const requiredFiles = [
  'scanner.js',
  'package.json',
  'README.md',
  'LICENSE',
];

let passed = 0;
let failed = 0;

for (const file of requiredFiles) {
  const fullPath = path.join(__dirname, file);
  if (fs.existsSync(fullPath)) {
    console.log(`  ✓ ${file}`);
    passed++;
  } else {
    console.log(`  ✗ ${file} MISSING`);
    failed++;
  }
}

// Verify package.json has required fields
const pkg = require('./package.json');
const requiredFields = ['name', 'version', 'description', 'main', 'dependencies'];
for (const field of requiredFields) {
  if (pkg[field]) {
    console.log(`  ✓ package.json:${field}`);
    passed++;
  } else {
    console.log(`  ✗ package.json:${field} MISSING`);
    failed++;
  }
}

// Verify hex-encode-utils is a dependency
if (pkg.dependencies && pkg.dependencies['hex-encode-utils']) {
  console.log(`  ✓ hex-encode-utils dependency`);
  passed++;
} else {
  console.log(`  ✗ hex-encode-utils NOT in dependencies`);
  failed++;
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
