#!/usr/bin/env node
'use strict';

const fs = require('fs');

const args = process.argv.slice(2);
const logPath = process.env.RB_FAKE_LOG_PATH;

if (logPath) {
  fs.appendFileSync(logPath, `${JSON.stringify(args)}\n`);
}

if (args[0] === 'sdk' && args[1] === 'bridge' && args[2] === 'manifest') {
  if (process.env.RB_FAKE_MANIFEST_MODE === 'empty') {
    process.exit(0);
  }

  if (process.env.RB_FAKE_MANIFEST_MODE === 'invalid') {
    process.stdout.write('not-json');
    process.exit(0);
  }

  process.stdout.write(
    JSON.stringify({
      version: '0.1.0',
      binary: 'redblue',
      commands: [
        {
          domain: 'dns',
          resource: 'record',
          description: 'DNS record lookups',
          machine_output: {
            global_flag: 'json',
            preferred_flag: 'format',
            preferred_value: 'json'
          },
          flags: [
            {
              long: 'type',
              short: 't',
              description: 'Record type',
              arg: 'TYPE',
              expects_value: true,
              camel_name: 'type',
              machine_output_role: null
            },
            {
              long: 'format',
              short: 'f',
              description: 'Output format (text, json)',
              arg: 'FORMAT',
              expects_value: true,
              camel_name: 'format',
              machine_output_role: 'preferred'
            }
          ],
          routes: [
            {
              verb: 'lookup',
              summary: 'Lookup DNS records',
              usage: 'rb dns record lookup <target> [--type TYPE]',
              positionals: [
                {
                  name: 'target',
                  required: true,
                  repeated: false,
                  slot: 'target',
                  index: 0
                }
              ]
            }
          ]
        },
        {
          domain: 'tls',
          resource: 'security',
          description: 'TLS audits',
          machine_output: {
            global_flag: 'json',
            preferred_flag: 'format',
            preferred_value: 'json'
          },
          flags: [
            {
              long: 'ports',
              short: 'p',
              description: 'Ports',
              arg: 'PORTS',
              expects_value: true,
              camel_name: 'ports',
              machine_output_role: null
            },
            {
              long: 'format',
              short: null,
              description: 'Output format (text, json)',
              arg: 'FORMAT',
              expects_value: true,
              camel_name: 'format',
              machine_output_role: 'preferred'
            }
          ],
          routes: [
            {
              verb: 'audit',
              summary: 'Audit TLS target',
              usage: 'rb tls security audit <target>',
              positionals: [
                {
                  name: 'target',
                  required: true,
                  repeated: false,
                  slot: 'target',
                  index: 0
                }
              ]
            }
          ]
        },
        {
          domain: 'network',
          resource: 'ports',
          description: 'Port scans',
          machine_output: {
            global_flag: 'json',
            preferred_flag: 'output',
            preferred_value: 'json'
          },
          flags: [
            {
              long: 'preset',
              short: null,
              description: 'Scan preset',
              arg: 'PRESET',
              expects_value: true,
              camel_name: 'preset',
              machine_output_role: null
            },
            {
              long: 'output',
              short: 'o',
              description: 'Output format (text, json)',
              arg: 'FORMAT',
              expects_value: true,
              camel_name: 'output',
              machine_output_role: 'preferred'
            }
          ],
          routes: [
            {
              verb: 'scan',
              summary: 'Scan ports',
              usage: 'rb network ports scan <target>',
              positionals: [
                {
                  name: 'target',
                  required: true,
                  repeated: false,
                  slot: 'target',
                  index: 0
                }
              ]
            }
          ]
        }
      ]
    })
  );
  process.exit(0);
}

if (process.env.RB_FAKE_ROUTE_MODE === 'invalid-json') {
  process.stdout.write('{');
  process.exit(0);
}

if (process.env.RB_FAKE_ROUTE_MODE === 'empty') {
  process.exit(0);
}

if (process.env.RB_FAKE_ROUTE_MODE === 'raw') {
  process.stdout.write(`raw:${args.join(' ')}`);
  process.exit(0);
}

if (process.env.RB_FAKE_ROUTE_MODE === 'spawn') {
  process.stdout.write(`spawn:${args.join(' ')}`);
  process.exit(0);
}

process.stdout.write(
  JSON.stringify({
    ok: true,
    argv: args
  })
);
