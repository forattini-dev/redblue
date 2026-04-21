'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const context = {
  Buffer,
  clearImmediate,
  clearInterval,
  clearTimeout,
  console,
  process,
  Promise,
  require,
  setImmediate,
  setInterval,
  setTimeout,
  URL,
  URLSearchParams,
};

context.__dirname = __dirname;
context.__filename = path.join(__dirname, 'redblue-sdk.js');
context.module = { exports: {} };
context.exports = context.module.exports;

vm.createContext(context);

const partFiles = ['redblue-sdk.part-a.js', 'redblue-sdk.part-b.js', 'redblue-sdk.part-c.js'];
for (const fileName of partFiles) {
  const filePath = path.join(__dirname, fileName);
  const source = fs.readFileSync(filePath, 'utf8');
  vm.runInContext(source, context, { filename: filePath, lineOffset: 0 });
}

module.exports = context.module.exports;

if (require.main === module) {
  module.exports.runCli().then((code) => {
    process.exitCode = code;
  });
}

