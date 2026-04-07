#!/usr/bin/env node
'use strict';

const fs = require('fs');

const args = process.argv.slice(2);
const logPath = process.env.RB_FAKE_LOG_PATH;

if (logPath) {
  fs.appendFileSync(logPath, `${JSON.stringify(args)}\n`);
}

if (args[0] === '--version') {
  const versionText = process.env.RB_FAKE_VERSION || 'RedBlue CLI v0.2.2\n';
  if (process.env.RB_FAKE_VERSION_STREAM === 'stderr') {
    process.stderr.write(versionText);
  } else {
    process.stdout.write(versionText);
  }
  process.exit(0);
}

if (args[0] === 'sdk' && args[1] === 'bridge' && args[2] === 'manifest') {
  if (process.env.RB_FAKE_MANIFEST_MODE === 'empty') {
    process.exit(0);
  }

  if (process.env.RB_FAKE_MANIFEST_MODE === 'invalid') {
    process.stdout.write('not-json');
    process.exit(0);
  }

  const manifest = {
      schema_version: 1,
      version: '0.2.2',
      binary: 'redblue',
      canonical_order: 'domain-resource-verb',
      canonical_grammar: 'rb <domain> <resource> <verb> [target] [args...] [flags]',
      global_options: [
        {
          long: 'json',
          short: 'j',
          description: 'Force JSON output globally',
          kind: 'machine-output',
          value: 'json'
        },
        {
          long: 'output',
          short: 'o',
          description: 'Select output format globally',
          kind: 'output-format',
          values: ['human', 'json', 'yaml']
        },
        {
          long: 'format',
          description: 'Alias for --output',
          kind: 'output-format',
          values: ['human', 'json', 'yaml']
        }
      ],
      domains: [
        {
          name: 'dns',
          aliases: [],
          resources: [
            {
              name: 'record',
              description: 'DNS record lookups',
              aliases: ['rec', 'records'],
              verbs: [
                {
                  name: 'lookup',
                  summary: 'Lookup DNS records',
                  aliases: []
                }
              ]
            }
          ]
        },
        {
          name: 'tls',
          aliases: [],
          resources: [
            {
              name: 'security',
              description: 'TLS audits',
              aliases: ['sec'],
              verbs: [
                {
                  name: 'audit',
                  summary: 'Audit TLS target',
                  aliases: []
                }
              ]
            }
          ]
        },
        {
          name: 'network',
          aliases: ['n', 'net', 'ntwrk'],
          resources: [
            {
              name: 'ports',
              description: 'Port scans',
              aliases: [],
              verbs: [
                {
                  name: 'scan',
                  summary: 'Scan ports',
                  aliases: []
                }
              ]
            }
          ]
        },
        {
          name: 'system',
          aliases: ['sys'],
          resources: [
            {
              name: 'host',
              description: 'Local host inventory',
              aliases: ['machine', 'node'],
              verbs: [
                {
                  name: 'inspect',
                  summary: 'Full local host inventory',
                  aliases: ['inventory', 'inv']
                },
                {
                  name: 'summary',
                  summary: 'Short local host summary',
                  aliases: ['sum']
                }
              ]
            }
          ]
        }
      ],
      commands: [
        {
          domain: 'dns',
          domain_aliases: [],
          resource: 'record',
          resource_aliases: ['rec', 'records'],
          description: 'DNS record lookups',
          canonical_order: 'domain-resource-verb',
          canonical_prefix: 'rb dns record',
          path: {
            domain: 'dns',
            resource: 'record'
          },
          aliases: [],
          machine_output: {
            global_flag: 'json',
            preferred_flag: 'format',
            preferred_value: 'json',
            json_support: 'best-effort',
            stdout_policy: 'json-only-when-requested',
            stderr_policy: 'diagnostics-only'
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
          examples: [
            {
              summary: 'Lookup MX records',
              command: 'rb dns record lookup example.com --type MX'
            }
          ],
          routes: [
            {
              verb: 'lookup',
              summary: 'Lookup DNS records',
              usage: 'rb dns record lookup <target> [--type TYPE]',
              aliases: [],
              canonical_path: 'dns/record/lookup',
              command: 'rb dns record lookup',
              machine_output: {
                global_flag: 'json',
                preferred_flag: 'format',
                preferred_value: 'json',
                json_support: 'best-effort',
                stdout_policy: 'json-only-when-requested',
                stderr_policy: 'diagnostics-only'
              },
              examples: [
                {
                  summary: 'Lookup MX records',
                  command: 'rb dns record lookup example.com --type MX'
                }
              ],
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
          domain_aliases: [],
          resource: 'security',
          resource_aliases: ['sec'],
          description: 'TLS audits',
          canonical_order: 'domain-resource-verb',
          canonical_prefix: 'rb tls security',
          path: {
            domain: 'tls',
            resource: 'security'
          },
          aliases: [],
          machine_output: {
            global_flag: 'json',
            preferred_flag: 'format',
            preferred_value: 'json',
            json_support: 'best-effort',
            stdout_policy: 'json-only-when-requested',
            stderr_policy: 'diagnostics-only'
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
          examples: [
            {
              summary: 'Audit a TLS endpoint',
              command: 'rb tls security audit example.com'
            }
          ],
          routes: [
            {
              verb: 'audit',
              summary: 'Audit TLS target',
              usage: 'rb tls security audit <target>',
              aliases: [],
              canonical_path: 'tls/security/audit',
              command: 'rb tls security audit',
              machine_output: {
                global_flag: 'json',
                preferred_flag: 'format',
                preferred_value: 'json',
                json_support: 'best-effort',
                stdout_policy: 'json-only-when-requested',
                stderr_policy: 'diagnostics-only'
              },
              examples: [
                {
                  summary: 'Audit a TLS endpoint',
                  command: 'rb tls security audit example.com'
                }
              ],
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
          domain_aliases: ['n', 'net', 'ntwrk'],
          resource: 'ports',
          resource_aliases: [],
          description: 'Port scans',
          canonical_order: 'domain-resource-verb',
          canonical_prefix: 'rb network ports',
          path: {
            domain: 'network',
            resource: 'ports'
          },
          aliases: [],
          machine_output: {
            global_flag: 'json',
            preferred_flag: 'output',
            preferred_value: 'json',
            json_support: 'best-effort',
            stdout_policy: 'json-only-when-requested',
            stderr_policy: 'diagnostics-only'
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
          examples: [
            {
              summary: 'Scan common ports',
              command: 'rb network ports scan 10.0.0.1 --preset common'
            }
          ],
          routes: [
            {
              verb: 'scan',
              summary: 'Scan ports',
              usage: 'rb network ports scan <target>',
              aliases: [],
              canonical_path: 'network/ports/scan',
              command: 'rb network ports scan',
              machine_output: {
                global_flag: 'json',
                preferred_flag: 'output',
                preferred_value: 'json',
                json_support: 'best-effort',
                stdout_policy: 'json-only-when-requested',
                stderr_policy: 'diagnostics-only'
              },
              examples: [
                {
                  summary: 'Scan common ports',
                  command: 'rb network ports scan 10.0.0.1 --preset common'
                }
              ],
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
          domain: 'system',
          domain_aliases: ['sys'],
          resource: 'host',
          resource_aliases: ['machine', 'node'],
          description: 'Local host inventory',
          canonical_order: 'domain-resource-verb',
          canonical_prefix: 'rb system host',
          path: {
            domain: 'system',
            resource: 'host'
          },
          aliases: [],
          machine_output: {
            global_flag: 'json',
            preferred_flag: null,
            preferred_value: null,
            json_support: 'guaranteed',
            stdout_policy: 'json-only-when-requested',
            stderr_policy: 'diagnostics-only'
          },
          flags: [],
          examples: [
            {
              summary: 'Inspect the local host',
              command: 'rb system host inspect --json'
            }
          ],
          routes: [
            {
              verb: 'inspect',
              summary: 'Full local host inventory',
              usage: 'rb system host inspect',
              aliases: ['inventory', 'inv'],
              canonical_path: 'system/host/inspect',
              command: 'rb system host inspect',
              machine_output: {
                global_flag: 'json',
                preferred_flag: null,
                preferred_value: null,
                json_support: 'guaranteed',
                stdout_policy: 'json-only-when-requested',
                stderr_policy: 'diagnostics-only'
              },
              examples: [
                {
                  summary: 'Inspect the local host',
                  command: 'rb system host inspect --json'
                }
              ],
              positionals: []
            },
            {
              verb: 'summary',
              summary: 'Short local host summary',
              usage: 'rb system host summary',
              aliases: ['sum'],
              canonical_path: 'system/host/summary',
              command: 'rb system host summary',
              machine_output: {
                global_flag: 'json',
                preferred_flag: null,
                preferred_value: null,
                json_support: 'guaranteed',
                stdout_policy: 'json-only-when-requested',
                stderr_policy: 'diagnostics-only'
              },
              examples: [
                {
                  summary: 'Summarize the local host',
                  command: 'rb system host summary --json'
                }
              ],
              positionals: []
            }
          ]
        }
      ]
    };

  if (process.env.RB_FAKE_MANIFEST_JSON_UNDECLARED === '1') {
    if (manifest.commands && manifest.commands[0] && manifest.commands[0].routes && manifest.commands[0].routes[0]) {
      manifest.commands[0].routes[0].machine_output = {
        ...manifest.commands[0].routes[0].machine_output,
        json_support: 'undeclared'
      };
    }
  }

  process.stdout.write(JSON.stringify(manifest));
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
