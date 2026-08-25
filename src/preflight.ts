/**
 * Two questions that must be answered before the action touches the host: was protection asked
 * for, and can this runner actually provide it.
 *
 * Both exist because of the same failure. `pre` and `post` have no `pre-if`/`post-if` in
 * action.yaml, so GitHub defaults them to `always()` and runs them even when the calling
 * workflow skips the main step. A repository that never opted in still got three `apt-get`
 * retries and a red "NO network protection" annotation on every build.
 *
 * The second question matters more. Safer Runner configures the host: it installs packages,
 * creates ipsets, rewrites iptables, replaces /etc/resolv.conf and restarts dnsmasq and rsyslog.
 * That needs real root and a service manager, which a GitHub-hosted runner has. A container
 * runner does not. Actions Runner Controller pods typically set
 * `securityContext.allowPrivilegeEscalation: false`, which sets the kernel's no_new_privs bit;
 * the kernel then ignores the setuid bit on /usr/bin/sudo and every privileged step fails before
 * sudo has even read sudoers, so no sudoers rule can work around it.
 *
 * Detecting that up front converts a slow, misleading failure - retried apt calls followed by a
 * job that quietly runs unprotected - into an immediate and accurate one.
 */

import * as exec from '@actions/exec';
import * as fs from 'fs';

/** Where the kernel reports the no_new_privs bit for the current process. */
const PROC_SELF_STATUS = '/proc/self/status';

/** Present only when systemd is the init system. This is the check sd_booted(3) makes. */
const SYSTEMD_RUNTIME_MARKER = '/run/systemd/system';

export interface PreflightResult {
  supported: boolean;
  /** One human-readable reason per failed check, in the order they were checked. */
  reasons: string[];
}

/**
 * Whether the caller asked for protection at all.
 *
 * Deliberately an explicit input rather than an inference from an empty `mode`: a workflow that
 * passes `mode: ${{ inputs.something-unset }}` should fail loudly, not silently lose its egress
 * control because a template variable was empty.
 */
export function isEnabled(enabledInput: string): boolean {
  return enabledInput.trim().toLowerCase() !== 'false';
}

/**
 * True when the kernel has set no_new_privs for this process.
 *
 * An unreadable /proc is treated as "not set". These checks exist to explain a known failure,
 * not to invent new reasons to refuse to run on a host that would have worked.
 */
export function hasNoNewPrivs(): boolean {
  try {
    return /^NoNewPrivs:\s*1\s*$/m.test(fs.readFileSync(PROC_SELF_STATUS, 'utf8'));
  } catch {
    return false;
  }
}

/** True when systemd is running and can be asked to restart dnsmasq and rsyslog. */
export function hasSystemd(): boolean {
  try {
    return fs.existsSync(SYSTEMD_RUNTIME_MARKER);
  } catch {
    return false;
  }
}

/** True when the runner user can reach root without a password prompt. */
export async function canSudoNonInteractively(): Promise<boolean> {
  try {
    return (await exec.exec('sudo', ['-n', 'true'], { ignoreReturnCode: true, silent: true })) === 0;
  } catch {
    return false;
  }
}

export async function checkRunnerSupport(): Promise<PreflightResult> {
  const reasons: string[] = [];

  if (hasNoNewPrivs()) {
    reasons.push(
      "the kernel's no_new_privs bit is set, so sudo cannot elevate - on Kubernetes this is what " +
        'securityContext.allowPrivilegeEscalation: false does'
    );
  } else if (!(await canSudoNonInteractively())) {
    // Only worth probing when no_new_privs has not already accounted for the failure.
    reasons.push('the runner user cannot run sudo without a password');
  }

  if (!hasSystemd()) {
    reasons.push('systemd is not running, so dnsmasq and rsyslog cannot be started or restarted');
  }

  return { supported: reasons.length === 0, reasons };
}

/**
 * Throw unless this runner can support the action.
 *
 * Callers decide how loud that is: the pre-hook reports it and lets the main step try, while the
 * main step fails the job. A workflow that asked for protection must never be able to finish
 * green without it.
 */
export async function assertRunnerSupported(): Promise<void> {
  const { supported, reasons } = await checkRunnerSupport();

  if (supported) {
    return;
  }

  throw new Error(
    `this runner cannot support Safer Runner: ${reasons.join('; ')}. ` +
      'Safer Runner configures the host, so it needs a GitHub-hosted runner or an equivalent VM ' +
      'with passwordless sudo and systemd. Container-based self-hosted runners - Actions Runner ' +
      'Controller pods, Docker executors - cannot provide that. Set enabled: false on those runners.'
  );
}
