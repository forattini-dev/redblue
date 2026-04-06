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
  positionals?: ManifestPositional[];
}

export interface ManifestMachineOutput {
  global_flag?: string;
  preferred_flag?: string;
  preferred_value?: string;
  description?: string;
}

export interface ManifestCommand {
  domain: string;
  resource: string;
  description?: string;
  hidden?: boolean;
  machine_output?: ManifestMachineOutput;
  flags: ManifestFlag[];
  routes: ManifestRoute[];
}

export interface SdkManifest {
  version: string;
  binary: string;
  machine_output?: ManifestMachineOutput;
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

export interface BinaryInstallResult extends BinaryInfo {
  source: string;
  changed: boolean;
  version?: string;
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

export interface RedblueClient {
  [domain: string]: ResourceBucket;
  $binaryPath: string;
  $manifest: SdkManifest;
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
  buildInvocation: (...args: unknown[]) => unknown;
  checkForUpdates: (...args: unknown[]) => unknown;
  createDomainProxy: (...args: unknown[]) => unknown;
  defaultInstallDir: (...args: unknown[]) => unknown;
  downloadToFile: (...args: unknown[]) => unknown;
  ensureInstalled: (...args: unknown[]) => unknown;
  ensureObject: (...args: unknown[]) => unknown;
  execFilePromise: (...args: unknown[]) => unknown;
  exists: (...args: unknown[]) => unknown;
  formatWrapperBinaryStatus: (...args: unknown[]) => unknown;
  formatWrapperHelp: (...args: unknown[]) => unknown;
  findFlag: (...args: unknown[]) => unknown;
  getBinaryInfo: (...args: unknown[]) => unknown;
  getParserCandidatePaths: (...args: unknown[]) => unknown;
  getDefaultBinaryName: (...args: unknown[]) => unknown;
  getInstalledVersion: (...args: unknown[]) => unknown;
  getReleaseTag: (...args: unknown[]) => unknown;
  invokeJson: (...args: unknown[]) => unknown;
  invokeRaw: (...args: unknown[]) => unknown;
  isExecutable: (...args: unknown[]) => unknown;
  kebabToCamel: (...args: unknown[]) => unknown;
  legacyInstallDir: (...args: unknown[]) => unknown;
  loadCliArgsParser: (...args: unknown[]) => unknown;
  normalizeReleaseTag: (...args: unknown[]) => unknown;
  parseWrapperArgs: (...args: unknown[]) => unknown;
  parseInstalledVersion: (...args: unknown[]) => unknown;
  request: (...args: unknown[]) => unknown;
  requestJson: (...args: unknown[]) => unknown;
  requestText: (...args: unknown[]) => unknown;
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
  waitForChild: (...args: unknown[]) => unknown;
  writeLine: (...args: unknown[]) => unknown;
  verifyChecksum: (...args: unknown[]) => unknown;
}

export function checkForUpdates(options?: WrapperOptions): Promise<WrapperStatus>;
export function createClient(options?: WrapperOptions): Promise<RedblueClient>;
export function downloadBinary(options?: WrapperOptions): Promise<string>;
export function ensureInstalled(options?: WrapperOptions): Promise<BinaryInstallResult>;
export function getBinaryInfo(options?: WrapperOptions): Promise<BinaryInfo>;
export function getManifest(options?: WrapperOptions): Promise<ManifestResult>;
export function getInstalledVersion(binaryPath: string, options?: ResolveOptions): Promise<string | null>;
export function runCli(argv?: string[], runtime?: CliInvocationRuntime): Promise<number>;
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
  createClient: typeof createClient;
  downloadBinary: typeof downloadBinary;
  ensureInstalled: typeof ensureInstalled;
  getBinaryInfo: typeof getBinaryInfo;
  getManifest: typeof getManifest;
  getInstalledVersion: typeof getInstalledVersion;
  runCli: typeof runCli;
  resolveAssetName: typeof resolveAssetName;
  resolveBinary: typeof resolveBinary;
  resolveBinaryWithInfo: typeof resolveBinaryWithInfo;
  upgradeBinary: typeof upgradeBinary;
  _internal: InternalNamespace;
  default: RedblueSdkExports;
}

declare const redblueSdk: RedblueSdkExports;

export = redblueSdk;
