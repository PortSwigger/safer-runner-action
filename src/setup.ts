/**
 * Shared setup functions for pre and main actions
 */

import * as core from '@actions/core';
import * as exec from '@actions/exec';
import * as crypto from 'crypto';
import * as fs from 'fs';
import { buildDnsConfig, DEFAULT_DNS_SERVER, SECONDARY_DNS_SERVER } from './config/dns-config-builder';
import { setupSudoLogging, removeSudoLogging, applyCustomSudoConfig, disableSudoForRunner } from './sudo';

export interface DnsUser {
  username: string;
  uid: number;
}

// Re-export sudo functions from the sudo module for backwards compatibility
export { setupSudoLogging, removeSudoLogging, applyCustomSudoConfig, disableSudoForRunner } from './sudo';

/**
 * Hardened apt options.
 *
 * GitHub-hosted runners have no IPv6 egress, but the runner image points apt at a failover
 * mirror list (`mirror+file:/etc/apt/apt-mirrors.txt`: azure.archive.ubuntu.com, then
 * archive.ubuntu.com, then security.ubuntu.com). When the Azure mirror is degraded apt falls
 * back to the public archives, which can resolve to IPv6. The SYN is then blackholed and apt
 * blocks in connect() indefinitely - observed as a 48 minute pre-hook hang with no output.
 *
 * - ForceIPv4          - never take the unreachable IPv6 path in the first place
 * - Acquire::*::Timeout - unset by default on noble, so nothing otherwise bounds that wait
 * - Acquire::Retries    - the runner image ships APT::Acquire::Retries "10", which multiplies
 *                         every stall; pin our own low value instead
 */
const APT_OPTIONS = [
  '-o',
  'Acquire::ForceIPv4=true',
  '-o',
  'Acquire::http::Timeout=15',
  '-o',
  'Acquire::https::Timeout=15',
  '-o',
  'Acquire::Retries=2'
];

/**
 * Wall-clock ceiling per apt invocation, as a backstop for anything the apt options miss.
 *
 * The update ceiling is set from measurement rather than taste: a successful `apt-get update`
 * took 22 seconds on one GitHub runner and 81 seconds on another. A ceiling near 81 seconds
 * would kill updates that were about to succeed and force a needless retry, so it sits well
 * clear of the slow case while still bounding a genuinely stalled mirror.
 */
const APT_UPDATE_DEADLINE_SECONDS = 150;
const APT_INSTALL_DEADLINE_SECONDS = 120;

const APT_MAX_ATTEMPTS = 3;
const APT_RETRY_DELAY_MS = 3000;

export const REQUIRED_PACKAGES = ['dnsmasq', 'ipset'];

export interface InstallDependenciesOptions {
  maxAttempts?: number;
  retryDelayMs?: number;
}

/**
 * Run one apt command under a hard wall-clock timeout.
 *
 * `timeout` runs as root under sudo so it can signal apt; `-k 10` follows up with SIGKILL if
 * apt ignores the SIGTERM. DEBIAN_FRONTEND is set via `env` because sudo does not forward it.
 */
async function runApt(deadlineSeconds: number, aptArgs: string[]): Promise<void> {
  await exec.exec('sudo', [
    'env',
    'DEBIAN_FRONTEND=noninteractive',
    'timeout',
    '-k',
    '10',
    deadlineSeconds.toString(),
    'apt-get',
    ...aptArgs,
    ...APT_OPTIONS
  ]);
}

/**
 * Install the packages the action needs, tolerating a transiently broken apt mirror.
 *
 * `apt-get update` exits 0 even when index downloads fail ("Some index files failed to
 * download. They have been ignored, or old ones used instead."), so its exit code alone does
 * not prove the package lists are usable. We therefore verify afterwards that the packages are
 * genuinely installed rather than trusting apt's status.
 */
export async function installDependencies(options: InstallDependenciesOptions = {}): Promise<void> {
  const maxAttempts = options.maxAttempts ?? APT_MAX_ATTEMPTS;
  const retryDelayMs = options.retryDelayMs ?? APT_RETRY_DELAY_MS;

  await retryApt('apt-get update', maxAttempts, retryDelayMs, () =>
    runApt(APT_UPDATE_DEADLINE_SECONDS, ['update', '-q'])
  );

  await retryApt('apt-get install', maxAttempts, retryDelayMs, () =>
    runApt(APT_INSTALL_DEADLINE_SECONDS, ['install', '-y', '-q', ...REQUIRED_PACKAGES])
  );

  await verifyPackagesInstalled();
}

async function retryApt(label: string, maxAttempts: number, retryDelayMs: number, run: () => Promise<void>) {
  let lastError: unknown;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      await run();
      return;
    } catch (error) {
      lastError = error;
      core.warning(`${label} failed (attempt ${attempt}/${maxAttempts}): ${error}`);

      if (attempt < maxAttempts) {
        await new Promise(resolve => setTimeout(resolve, retryDelayMs));
      }
    }
  }

  throw new Error(`${label} failed after ${maxAttempts} attempts: ${lastError}`);
}

/**
 * Confirm the packages are actually installed.
 *
 * Without this a degraded mirror produces `apt-get update` exit 0 followed by
 * `E: Unable to locate package dnsmasq`, and the caller carries on believing setup worked.
 */
async function verifyPackagesInstalled(): Promise<void> {
  const exitCode = await exec.exec('dpkg-query', ['-s', ...REQUIRED_PACKAGES], {
    ignoreReturnCode: true,
    silent: true
  });

  if (exitCode !== 0) {
    throw new Error(
      `Required packages are not installed after apt-get install: ${REQUIRED_PACKAGES.join(', ')}. ` +
        'The apt mirror is likely unreachable from this runner.'
    );
  }
}

/**
 * Perform initial system setup: install dependencies, create DNS user, setup ipsets, create log directory
 * Note: Sudo logging is NOT configured here - it's set up at the end of pre/main actions
 * to avoid capturing setup commands
 * Returns the created DNS user
 */
export async function performInitialSetup(): Promise<DnsUser> {
  // Install dependencies
  core.info('Installing dependencies...');
  await installDependencies();

  // Create log directory for all safer-runner logs
  core.info('Creating log directory...');
  await createLogDirectory();

  // Create random DNS user for privilege separation
  core.info('Creating isolated DNS user...');
  const dnsUser = await createRandomDNSUser();
  core.info(`Created isolated DNS user: ${dnsUser.username} (UID: ${dnsUser.uid})`);

  // Configure ipsets
  core.info('Configuring ipsets...');
  await setupIpsets();

  return dnsUser;
}

/**
 * Create /var/log/safer-runner directory with proper permissions
 * This directory will contain all safer-runner log files (DNS, iptables, sudo)
 */
export async function createLogDirectory(): Promise<void> {
  const logDir = '/var/log/safer-runner';

  // Create directory
  await exec.exec('sudo', ['mkdir', '-p', logDir]);

  // Set ownership to syslog:adm (rsyslog runs as syslog, runner is in adm group)
  await exec.exec('sudo', ['chown', 'syslog:adm', logDir]);

  // Make directory readable by all (so runner can read logs without sudo)
  await exec.exec('sudo', ['chmod', '755', logDir]);
}

export async function createRandomDNSUser(): Promise<DnsUser> {
  // Generate random username with 16 hex characters
  const randomHex = crypto.randomBytes(8).toString('hex');
  const username = `dns-${randomHex}`;

  // Generate random UID in safe range (60000-65000 to avoid conflicts)
  const uid = 60000 + Math.floor(Math.random() * 5000);

  // Create system user with no login, no home directory
  await exec.exec('sudo', [
    'useradd',
    '--system',
    '--no-create-home',
    '--shell',
    '/usr/sbin/nologin',
    '--uid',
    uid.toString(),
    username
  ]);

  return { username, uid };
}

export async function setupIpsets() {
  // Create ipsets for allowlisting
  await exec.exec('sudo', [
    'ipset',
    'create',
    'github',
    'hash:ip',
    'family',
    'inet',
    'hashsize',
    '1024',
    'maxelem',
    '10000'
  ]);
  await exec.exec('sudo', [
    'ipset',
    'create',
    'user',
    'hash:ip',
    'family',
    'inet',
    'hashsize',
    '1024',
    'maxelem',
    '10000'
  ]);
}

/**
 * Setup rsyslog to filter iptables logs to dedicated files
 * This allows reading logs without sudo and provides clean separation
 * between pre-hook and main action logs
 *
 * Creates separate config files for pre-hook and main action to avoid
 * overwriting each other's configurations
 */
export async function setupIptablesLogging(
  logFile: string,
  logPrefixes: string[],
  configSuffix: string = ''
): Promise<void> {
  // Build rsyslog configuration to filter iptables logs
  // Filter by programname=kernel to only capture actual iptables log messages
  // (not sudo commands that set up the logging rules)
  const prefixArray = "['" + logPrefixes.join("', '") + "']";

  const rsyslogConfig = `if $programname == 'kernel' and $msg contains ${prefixArray} then ${logFile}
`;

  // Use different config file names for pre-hook and main action
  const configFile = configSuffix
    ? `/etc/rsyslog.d/10-iptables-safer-runner-${configSuffix}.conf`
    : '/etc/rsyslog.d/10-iptables-safer-runner.conf';

  // Write rsyslog configuration
  await exec.exec('sudo', ['tee', configFile], {
    input: Buffer.from(rsyslogConfig)
  });

  // Create log file and set ownership to syslog user (rsyslog runs as syslog:adm)
  // This allows rsyslog to write to the file
  await exec.exec('sudo', ['touch', logFile]);
  await exec.exec('sudo', ['chown', 'syslog:adm', logFile]);
  await exec.exec('sudo', ['chmod', '644', logFile]);

  // Restart rsyslog to apply configuration
  await exec.exec('sudo', ['systemctl', 'restart', 'rsyslog']);
}

/**
 * Setup iptables firewall rules
 *
 * IMPORTANT: The DNS server parameters MUST match what will be configured in setupDNSMasq().
 * If you add custom DNS server inputs to the action, you MUST pass them to both functions.
 *
 * @param dnsUid - UID of the DNS user (dnsmasq will run as this user)
 * @param logPrefix - Prefix for iptables log messages (e.g., 'Pre-' or 'Main-')
 * @param primaryDnsServer - Primary DNS server IP (defaults to Quad9: 9.9.9.9)
 * @param secondaryDnsServer - Secondary DNS server IP (defaults to Quad9: 149.112.112.112)
 */
export interface OutputRuleOptions {
  dnsUid: number;
  logPrefix: string;
  primaryDnsServer: string;
  secondaryDnsServer: string;
}

/**
 * Build the OUTPUT chain rules in iptables-restore syntax.
 *
 * Kept as a pure function so the rule set can be asserted directly in tests - these rules are
 * the network half of the security model and a silent typo would not otherwise be caught.
 *
 * Note the quoting on --log-prefix: the prefixes carry a trailing space that the rsyslog
 * filters match on, and iptables-restore would otherwise drop it.
 */
export function buildOutputRules(options: OutputRuleOptions): string[] {
  const { dnsUid, logPrefix, primaryDnsServer, secondaryDnsServer } = options;

  const rules = [
    // Allow established connections on eth0
    '-A OUTPUT -o eth0 -m conntrack --ctstate ESTABLISHED -j ACCEPT',

    // Allow Azure metadata service (required for GitHub Actions)
    '-A OUTPUT -o eth0 -d 168.63.129.16 -j ACCEPT',
    '-A OUTPUT -o eth0 -d 169.254.169.254 -j ACCEPT',

    // Log then allow GitHub ipset matches
    `-A OUTPUT -o eth0 -m set --match-set github dst -j LOG --log-prefix "${logPrefix}GitHub-Allow: "`,
    '-A OUTPUT -o eth0 -m set --match-set github dst -j ACCEPT',

    // Log then allow user-allowed ipset matches
    `-A OUTPUT -o eth0 -m set --match-set user dst -j LOG --log-prefix "${logPrefix}User-Allow: "`,
    '-A OUTPUT -o eth0 -m set --match-set user dst -j ACCEPT',

    // Allow DNS to our upstream servers - only from the random DNS user UID
    `-A OUTPUT -o eth0 -d ${primaryDnsServer} -p udp --dport 53 -m owner --uid-owner ${dnsUid} -j ACCEPT`,

    // Drop ICMP destination-unreachable without logging: these are kernel-generated
    // responses to DNS queries, not security-relevant
    `-A OUTPUT -o eth0 -d ${primaryDnsServer} -p icmp --icmp-type destination-unreachable -j DROP`
  ];

  if (secondaryDnsServer) {
    rules.push(
      `-A OUTPUT -o eth0 -d ${secondaryDnsServer} -p udp --dport 53 -m owner --uid-owner ${dnsUid} -j ACCEPT`,
      `-A OUTPUT -o eth0 -d ${secondaryDnsServer} -p icmp --icmp-type destination-unreachable -j DROP`
    );
  }

  return rules;
}

/**
 * Build the terminal OUTPUT rules: default deny in enforce mode, log-and-allow in analyze mode.
 * Applied separately from buildOutputRules() so the default-deny lands only once the DNS layer
 * is ready.
 */
export function buildTerminalRules(mode: string, logPrefix: string): string[] {
  if (mode === 'enforce') {
    return [`-A OUTPUT -o eth0 -j LOG --log-prefix "${logPrefix}Drop-Enforce: "`, '-A OUTPUT -o eth0 -j DROP'];
  }

  return [`-A OUTPUT -o eth0 -j LOG --log-prefix "${logPrefix}Allow-Analyze: "`, '-A OUTPUT -o eth0 -j ACCEPT'];
}

/**
 * Append rules to the filter table in a single iptables-restore call.
 *
 * --noflush is essential: without it iptables-restore replaces every chain in the filter
 * table, wiping INPUT and FORWARD, which validation.ts baselines and would then report as
 * tampering.
 */
async function applyOutputRules(rules: string[]): Promise<void> {
  const script = `*filter\n${rules.join('\n')}\nCOMMIT\n`;

  await exec.exec('sudo', ['iptables-restore', '--noflush'], {
    input: Buffer.from(script)
  });
}

/**
 * Setup iptables firewall rules
 *
 * IMPORTANT: The DNS server parameters MUST match what will be configured in setupDNSMasq().
 * If you add custom DNS server inputs to the action, you MUST pass them to both functions.
 *
 * @param dnsUid - UID of the DNS user (dnsmasq will run as this user)
 * @param logPrefix - Prefix for iptables log messages (e.g., 'Pre-' or 'Main-')
 * @param primaryDnsServer - Primary DNS server IP (defaults to Quad9: 9.9.9.9)
 * @param secondaryDnsServer - Secondary DNS server IP (defaults to Quad9: 149.112.112.112)
 */
export async function setupFirewallRules(
  dnsUid: number,
  logPrefix: string = '',
  primaryDnsServer: string = DEFAULT_DNS_SERVER,
  secondaryDnsServer: string = SECONDARY_DNS_SERVER
): Promise<void> {
  // Flush OUTPUT only - INPUT and FORWARD are deliberately left alone
  await exec.exec('sudo', ['iptables', '-F', 'OUTPUT']);

  await applyOutputRules(buildOutputRules({ dnsUid, logPrefix, primaryDnsServer, secondaryDnsServer }));
}

export async function setupDNSConfig(): Promise<void> {
  // Configure systemd-resolved to use our DNS server
  await exec.exec('sudo', ['mkdir', '-p', '/etc/systemd/resolved.conf.d']);

  const resolvedConfig = `[Resolve]
DNS=127.0.0.1
DNSSEC=yes
DNSStubListener=no`;

  await exec.exec('sudo', ['tee', '/etc/systemd/resolved.conf.d/no-stub.conf'], {
    input: Buffer.from(resolvedConfig)
  });

  // Update resolv.conf to use localhost
  await exec.exec('sudo', ['unlink', '/etc/resolv.conf']);
  await exec.exec('sudo', ['tee', '/etc/resolv.conf'], {
    input: Buffer.from('nameserver 127.0.0.1\n')
  });
}

export async function setupDNSMasq(
  mode: string,
  allowedDomains: string,
  blockRiskySubdomains: boolean,
  dnsUsername: string,
  logFile?: string,
  primaryDnsServer?: string,
  secondaryDnsServer?: string
): Promise<string[]> {
  // Build DNS configuration using the config builder module
  const { config: dnsmasqConfig, blockedSubdomains } = buildDnsConfig({
    mode: mode as 'analyze' | 'enforce',
    allowedDomains,
    blockRiskySubdomains,
    dnsUsername,
    logFile,
    primaryDnsServer,
    secondaryDnsServer
  });

  // Write configuration to file
  await exec.exec('sudo', ['tee', '/etc/dnsmasq.conf'], {
    input: Buffer.from(dnsmasqConfig)
  });

  // Restrict permissions - only root should read the DNS username
  await exec.exec('sudo', ['chmod', '600', '/etc/dnsmasq.conf']);
  await exec.exec('sudo', ['chown', 'root:root', '/etc/dnsmasq.conf']);

  return blockedSubdomains;
}

export interface RestartServicesOptions {
  /** Skip the systemd-resolved restart when the pre-hook already applied the same config */
  skipResolvedRestart?: boolean;
  /** How long to wait for dnsmasq to create its log file */
  logFileTimeoutMs?: number;
  /** How often to check for it */
  pollIntervalMs?: number;
}

const LOG_FILE_TIMEOUT_MS = 5000;
const LOG_FILE_POLL_INTERVAL_MS = 50;

export async function restartServices(logFile?: string, options: RestartServicesOptions = {}): Promise<void> {
  // systemd-resolved only needs restarting once per job: setupDNSConfig() writes identical
  // content every time, so a second restart is pure latency.
  if (!options.skipResolvedRestart) {
    await exec.exec('sudo', ['systemctl', 'restart', 'systemd-resolved']);
  }

  await exec.exec('sudo', ['systemctl', 'restart', 'dnsmasq']);

  if (!logFile) {
    return;
  }

  // dnsmasq creates its log file as 0640, so the runner cannot read it without sudo.
  // Poll for the file rather than sleeping a fixed interval: a sleep that is too short makes
  // the chmod fail on a missing file and aborts the whole setup, and one that is long enough
  // to be safe is wasted time on every run.
  const appeared = await waitForFile(
    logFile,
    options.logFileTimeoutMs ?? LOG_FILE_TIMEOUT_MS,
    options.pollIntervalMs ?? LOG_FILE_POLL_INTERVAL_MS
  );

  if (!appeared) {
    core.warning(
      `dnsmasq did not create ${logFile}. DNS activity will be missing from the security report. ` +
        'Check `systemctl status dnsmasq`.'
    );
    return;
  }

  await exec.exec('sudo', ['chmod', '0644', logFile]);
}

/** Poll for a path to exist, returning false if it never shows up within the timeout */
async function waitForFile(filePath: string, timeoutMs: number, pollIntervalMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;

  for (;;) {
    if (fs.existsSync(filePath)) {
      return true;
    }

    if (Date.now() >= deadline) {
      return false;
    }

    await new Promise(resolve => setTimeout(resolve, pollIntervalMs));
  }
}

export async function finalizeFirewallRules(mode: string, logPrefix: string = ''): Promise<void> {
  await applyOutputRules(buildTerminalRules(mode, logPrefix));
}
