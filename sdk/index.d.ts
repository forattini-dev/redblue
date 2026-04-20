import type {
  GeneratedCanonicalRoutePath,
  GeneratedRouteSurface,
  GeneratedRouteTuple
} from './generated-routes';

export interface ExecResult {
  code: number;
  stdout: string;
  stderr: string;
  args: string[];
}

export interface CliInvocationRuntime {
  stdout?: {
    write(chunk: string | Uint8Array): void;
  };
  stderr?: {
    write(chunk: string | Uint8Array): void;
  };
  env?: Record<string, string | undefined>;
  localParserPath?: string;
  parserModule?: Record<string, unknown>;
  parserCandidates?: string[];
  parserOptions?: Record<string, unknown>;
  importModule?: (specifier: string) => Promise<Record<string, unknown>>;
  [key: string]: unknown;
}

export interface ManifestFlag {
  long: string;
  short?: string;
  description: string;
  default?: unknown;
  arg?: string;
  values?: string[];
  expects_value: boolean;
  camel_name: string;
  machine_output_role?: 'preferred' | string;
}

export interface ManifestPositional {
  name: string;
  required: boolean;
  repeated: boolean;
  slot: 'target' | 'arg';
  index: number;
}

export interface ManifestRoute {
  verb: string;
  summary?: string;
  usage?: string;
  aliases?: string[];
  canonical_path?: string;
  command?: string;
  machine_output?: ManifestMachineOutput;
  positionals?: ManifestPositional[];
}

export interface ManifestVerbNode {
  name: string;
  summary?: string;
  aliases?: string[];
}

export interface ManifestResourceNode {
  name: string;
  description?: string;
  aliases?: string[];
  verbs?: ManifestVerbNode[];
}

export interface ManifestDomainNode {
  name: string;
  aliases?: string[];
  resources?: ManifestResourceNode[];
}

export interface ManifestMachineOutput {
  global_flag?: string;
  preferred_flag?: string;
  preferred_value?: string;
  json_support?: 'undeclared' | 'best-effort' | 'guaranteed' | string;
  stdout_policy?: 'mixed' | 'json-only-when-requested' | string;
  stderr_policy?: 'mixed' | 'diagnostics-only' | string;
  description?: string;
}

export interface ManifestGlobalOption {
  long: string;
  short?: string;
  description?: string;
  kind?: 'machine-output' | 'output-format' | string;
  value?: string;
  values?: string[];
}

export interface ManifestCommand {
  domain: string;
  domain_aliases?: string[];
  resource: string;
  resource_aliases?: string[];
  description?: string;
  hidden?: boolean;
  canonical_order?: string;
  canonical_prefix?: string;
  path?: {
    domain: string;
    resource: string;
  };
  aliases?: string[];
  machine_output?: ManifestMachineOutput;
  flags: ManifestFlag[];
  routes: ManifestRoute[];
}

export interface ManifestCommandCatalogEntry {
  domain: string;
  domain_aliases?: string[];
  resource: string;
  resource_aliases?: string[];
  verb: string;
  route_aliases?: string[];
  canonical_path: string;
  command: string;
  summary?: string;
  usage?: string;
  flags?: ManifestFlag[];
  positionals?: ManifestPositional[];
  examples?: Array<{ summary?: string; command: string }>;
  machine_output?: ManifestMachineOutput;
}

export interface ManifestCompletionEntry {
  value: string;
  kind:
    | 'domain'
    | 'resource'
    | 'verb'
    | 'command'
    | 'flag'
    | 'flag-value'
    | 'target'
    | 'positional'
    | string;
  summary?: string;
  aliases?: string[];
  command?: string;
}

export interface SdkManifest {
  schema_version?: number;
  version: string;
  binary: string;
  canonical_order?: string;
  canonical_grammar?: string;
  machine_output?: ManifestMachineOutput;
  global_options?: ManifestGlobalOption[];
  domains?: ManifestDomainNode[];
  commands: ManifestCommand[];
}

export interface WrapperOptionSet {
  binaryPath?: string;
  targetDir?: string;
  autoDownload?: boolean;
  binaryName?: string;
  channel?: 'stable' | 'latest' | 'next';
  force?: boolean;
  githubToken?: string;
  repo?: string;
  releaseVersion?: string;
  version?: string;
  staticBuild?: boolean;
  verify?: boolean;
  source?: string;
  assetName?: string;
  preferSystemBinary?: boolean;
  cwd?: string;
  env?: Record<string, string | undefined>;
  timeout?: number;
  maxBuffer?: number;
  stdio?: 'inherit' | 'pipe' | 'ignore' | string | (string | number | null)[];
}

export interface WrapperOptions extends WrapperOptionSet {
  'binary-path'?: string;
  'target-dir'?: string;
  'auto-download'?: boolean;
  'asset-name'?: string;
  'github-token'?: string;
  'release-version'?: string;
  'static-build'?: boolean;
}

export interface WrapperStatus {
  binaryPath: string;
  currentVersion: string | null;
  latestVersion: string;
  source?: string | null;
  hasUpdate: boolean;
}

export interface BinaryInfo {
  binaryPath: string;
  source?: string;
  version?: string | null;
}

export type BinaryInstallStatus = 'ready' | 'downloaded' | 'stale' | 'offline';

export interface BinaryInstallResult extends BinaryInfo {
  status: BinaryInstallStatus;
  source: string;
  changed: boolean;
  version?: string;
  latestVersion?: string | null;
}

export interface EnsureInstalledOptions extends WrapperOptions {
  skipIfFresh?: boolean;
}

export declare class RedblueError extends Error {
  readonly code: string;
  readonly cause?: unknown;
  constructor(message: string, options?: { code?: string; cause?: unknown });
}

export declare class RedblueBinaryNotFoundError extends RedblueError {
  readonly binaryPath?: string;
}

export declare class RedblueRouteError extends RedblueError {
  readonly route?: string;
  readonly selector?: string[];
}

export declare class RedblueParseError extends RedblueError {
  readonly stdout?: string;
  readonly stderr?: string;
  readonly args?: string[];
}

export declare class RedblueTimeoutError extends RedblueError {
  readonly timeout?: number;
  readonly args?: string[];
}

export declare class RedblueChecksumError extends RedblueError {
  readonly expected?: string;
  readonly actual?: string;
}

export declare class RedblueNetworkError extends RedblueError {
  readonly statusCode?: number;
  readonly url?: string;
}

export interface BinaryUpgradeResult {
  binaryPath: string;
  previousVersion: string | null;
  version: string;
  changed: boolean;
  source?: string;
}

export interface ResolveOptions {
  cwd?: string;
  env?: Record<string, string | undefined>;
  timeout?: number;
  maxBuffer?: number;
  stdio?: 'inherit' | 'pipe' | 'ignore' | string | (string | number | null)[];
}

export interface InvocationOptions extends ResolveOptions {
  json?: boolean;
}

export interface RouteInput {
  target?: string;
  args?: string[];
  flags?: Record<string, unknown>;
  cwd?: string;
  env?: Record<string, string | undefined>;
  timeout?: number;
  maxBuffer?: number;
  stdio?: 'inherit' | 'pipe' | 'ignore' | string | (string | number | null)[];
  [key: string]: unknown;
}

export type RouteInvocation<T = unknown> = {
  <TResult = T>(input?: RouteInput, options?: InvocationOptions): Promise<TResult>;
  raw(input?: RouteInput, options?: InvocationOptions): Promise<ExecResult>;
  spawn(input?: RouteInput, options?: ResolveOptions & { detached?: boolean }): unknown;
  meta: { command: ManifestCommand; route: ManifestRoute };
};

export type RouteBucket = {
  [verb: string]: RouteInvocation;
};

export type ResourceBucket = {
  [resource: string]: RouteBucket;
};

export type RouteSelector =
  | GeneratedCanonicalRoutePath
  | GeneratedRouteTuple
  | string
  | [string, string, string];

export interface RedblueClient extends GeneratedRouteSurface<RouteInvocation> {
  [domain: string]: ResourceBucket;
  $binaryPath: string;
  $manifest: SdkManifest;
  $routes: Record<GeneratedCanonicalRoutePath, RouteInvocation> & Record<string, RouteInvocation>;
  $domains: ManifestDomainNode[];
  $commands: ManifestCommandCatalogEntry[];
  $cliSchema: Record<string, unknown>;
  $createCLI(runtime?: CliInvocationRuntime): Promise<unknown>;
  $findRoute(selector: RouteSelector): RouteInvocation | null;
  $complete(selector?: string | string[]): {
    stage: 'domain' | 'resource' | 'verb' | 'command' | 'flag' | 'flag-value' | 'target' | 'positional' | string;
    completions: ManifestCompletionEntry[];
  };
  $describe(selector: RouteSelector): ManifestCommandCatalogEntry | null;
  $help(selector: RouteSelector): string;
  $suggest(selector?: string | string[]): {
    stage: 'domain' | 'resource' | 'verb' | 'command' | string;
    suggestions: string[];
  };
  $downloadBinary: typeof downloadBinary;
  $resolveBinary: typeof resolveBinary;
  $exec: typeof execFile;
  $spawn: typeof spawnChild;
}

export interface ManifestResult {
  binaryPath: string;
  manifest: SdkManifest;
}

export interface CliResult {
  passthroughArgs: string[];
  rawArgs: string[];
  usedDoubleDash: boolean;
}

export interface InternalNamespace {
  attachRoute: (...args: unknown[]) => unknown;
  buildDomainCatalog: (...args: unknown[]) => unknown;
  buildCommandCatalog: (...args: unknown[]) => unknown;
  buildManifestCliSchema: (...args: unknown[]) => unknown;
  buildJsonCliArgs: (...args: unknown[]) => unknown;
  buildInvocation: (...args: unknown[]) => unknown;
  checkForUpdates: (...args: unknown[]) => unknown;
  createManifestCLI: typeof createManifestCLI;
  createDomainProxy: (...args: unknown[]) => unknown;
  createRouteIndex: (...args: unknown[]) => unknown;
  defaultInstallDir: (...args: unknown[]) => unknown;
  downloadToFile: (...args: unknown[]) => unknown;
  ensureInstalled: (...args: unknown[]) => unknown;
  ensureObject: (...args: unknown[]) => unknown;
  execFilePromise: (...args: unknown[]) => unknown;
  exists: (...args: unknown[]) => unknown;
  formatManifestHelpSummary: (...args: unknown[]) => unknown;
  formatRouteHelpSummary: (...args: unknown[]) => unknown;
  formatWrapperBinaryStatus: (...args: unknown[]) => unknown;
  formatWrapperHelp: (...args: unknown[]) => unknown;
  findFlag: (...args: unknown[]) => unknown;
  getBinaryInfo: (...args: unknown[]) => unknown;
  getParserCandidatePaths: (...args: unknown[]) => unknown;
  getDefaultBinaryName: (...args: unknown[]) => unknown;
  getInstalledVersion: (...args: unknown[]) => unknown;
  getReleaseTag: (...args: unknown[]) => unknown;
  hasLongFlag: (...args: unknown[]) => unknown;
  findRouteInvocation: (...args: unknown[]) => unknown;
  describeManifestRoute: (...args: unknown[]) => unknown;
  completeManifestTokens: (...args: unknown[]) => unknown;
  invokeJson: (...args: unknown[]) => unknown;
  invokeRaw: (...args: unknown[]) => unknown;
  isExecutable: (...args: unknown[]) => unknown;
  kebabToCamel: (...args: unknown[]) => unknown;
  legacyInstallDir: (...args: unknown[]) => unknown;
  loadCliArgsParser: (...args: unknown[]) => unknown;
  looksLikeCanonicalCommandArgs: (...args: unknown[]) => unknown;
  normalizeCliArgv: (...args: unknown[]) => unknown;
  normalizeReleaseTag: (...args: unknown[]) => unknown;
  normalizeTokenSelector: (...args: unknown[]) => unknown;
  normalizeRouteSelector: (...args: unknown[]) => unknown;
  parseWrapperArgs: (...args: unknown[]) => unknown;
  parseInstalledVersion: (...args: unknown[]) => unknown;
  request: (...args: unknown[]) => unknown;
  requestJson: (...args: unknown[]) => unknown;
  requestText: (...args: unknown[]) => unknown;
  routeInvocationMeta: (...args: unknown[]) => unknown;
  resolveMachineOutput: (...args: unknown[]) => unknown;
  routeIdentifier: (...args: unknown[]) => unknown;
  runJson: typeof runJson;
  suggestCommandTokens: (...args: unknown[]) => unknown;
  resolveFromPath: (...args: unknown[]) => unknown;
  resolveBinaryWithInfo: (...args: unknown[]) => unknown;
  resolveLegacyBinaryPath: (...args: unknown[]) => unknown;
  resolveManagedBinaryPath: (...args: unknown[]) => unknown;
  resolveManagedUpgradeDestination: (...args: unknown[]) => unknown;
  sha256File: (...args: unknown[]) => unknown;
  splitWrapperArgs: (...args: unknown[]) => unknown;
  spawnBinary: (...args: unknown[]) => unknown;
  toImportSpecifier: (...args: unknown[]) => unknown;
  upgradeBinary: (...args: unknown[]) => unknown;
  validateManifestCommandArgs: (...args: unknown[]) => unknown;
  waitForChild: (...args: unknown[]) => unknown;
  writeLine: (...args: unknown[]) => unknown;
  verifyChecksum: (...args: unknown[]) => unknown;
}

/** SDK version string (e.g. "0.2.2"), read from package.json at load time. */
export const version: string;

export function checkForUpdates(options?: WrapperOptions): Promise<WrapperStatus>;
export function createManifestCLI(
  options?: WrapperOptions,
  runtime?: CliInvocationRuntime
): Promise<unknown>;
export function createClient(options?: WrapperOptions): Promise<RedblueClient>;
export function downloadBinary(options?: WrapperOptions): Promise<string>;
export function ensureInstalled(options?: EnsureInstalledOptions): Promise<BinaryInstallResult>;
export function getBinaryInfo(options?: WrapperOptions): Promise<BinaryInfo>;
export function getManifest(options?: WrapperOptions): Promise<ManifestResult>;
export function getInstalledVersion(binaryPath: string, options?: ResolveOptions): Promise<string | null>;
export function runCli(argv?: string[], runtime?: CliInvocationRuntime): Promise<number>;
export function runJson(argv?: string[], options?: WrapperOptions): Promise<unknown>;
export function resolveAssetName(options?: WrapperOptions): string;
export function resolveBinary(options?: WrapperOptions): Promise<string>;
export function resolveBinaryWithInfo(
  options?: WrapperOptions
): Promise<{
  binaryPath: string;
  source: string;
  version?: string;
}>;
export function upgradeBinary(options?: WrapperOptions): Promise<BinaryUpgradeResult>;
export function execFile(
  binaryPath: string,
  args: string[],
  options?: ResolveOptions
): Promise<ExecResult>;
export function spawnChild(
  binaryPath: string,
  args: string[],
  options?: ResolveOptions & { detached?: boolean }
): unknown;

export interface RedblueSdkExports {
  checkForUpdates: typeof checkForUpdates;
  createManifestCLI: typeof createManifestCLI;
  createClient: typeof createClient;
  downloadBinary: typeof downloadBinary;
  ensureInstalled: typeof ensureInstalled;
  getBinaryInfo: typeof getBinaryInfo;
  getManifest: typeof getManifest;
  getInstalledVersion: typeof getInstalledVersion;
  runCli: typeof runCli;
  runJson: typeof runJson;
  resolveAssetName: typeof resolveAssetName;
  resolveBinary: typeof resolveBinary;
  resolveBinaryWithInfo: typeof resolveBinaryWithInfo;
  upgradeBinary: typeof upgradeBinary;
  RedblueError: typeof RedblueError;
  RedblueBinaryNotFoundError: typeof RedblueBinaryNotFoundError;
  RedblueRouteError: typeof RedblueRouteError;
  RedblueParseError: typeof RedblueParseError;
  RedblueTimeoutError: typeof RedblueTimeoutError;
  RedblueChecksumError: typeof RedblueChecksumError;
  RedblueNetworkError: typeof RedblueNetworkError;
  _internal: InternalNamespace;
  default: RedblueSdkExports;
}

declare const redblueSdk: RedblueSdkExports;

export = redblueSdk;
