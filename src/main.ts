import * as core from '@actions/core';
import { SystemValidator } from './validation';
import {
  type DnsUser,
  performInitialSetup,
  setupFirewallRules,
  setupDNSConfig,
  setupDNSMasq,
  restartServices,
  finalizeFirewallRules,
  setupIptablesLogging
} from './setup';
import { removeSudoLogging, setupSudoLogging, disableSudoForRunner, applyCustomSudoConfig } from './sudo';
import { disableDockerForRunner, stopDockerService } from './docker';
import { assertRunnerSupported, isEnabled } from './preflight';

async function run(): Promise<void> {
  try {
    if (!isEnabled(core.getInput('enabled'))) {
      core.info('Safer Runner is disabled for this job (enabled: false) - no protection applied.');
      return;
    }

    const mode = core.getInput('mode') || 'analyze';
    const allowedDomains = core.getInput('allowed-domains') || '';
    const primaryDnsServer = core.getInput('primary-dns-server') || '9.9.9.9';
    const secondaryDnsServer = core.getInput('secondary-dns-server') || '149.112.112.112';
    const blockRiskySubdomains = core.getBooleanInput('block-risky-github-subdomains');
    const disableSudo = core.getBooleanInput('disable-sudo');
    const sudoConfig = core.getInput('sudo-config') || '';
    const disableDocker = core.getBooleanInput('disable-docker');
    const stopDocker = core.getBooleanInput('stop-docker');

    // Validate sudo-related inputs
    if (disableSudo && sudoConfig) {
      core.warning(
        '⚠️ Both disable-sudo and sudo-config are set. Ignoring sudo-config (disable-sudo takes precedence).'
      );
    }

    // Validate Docker-related inputs
    if (stopDocker && disableDocker) {
      core.warning('⚠️ Both stop-docker and disable-docker are set. stop-docker takes precedence (more restrictive).');
    }

    // A job that asked for protection must not be able to finish green without it, so an
    // unsupported runner fails here rather than degrading quietly the way the pre-hook does.
    await assertRunnerSupported();

    // Remove sudo logging config from pre-hook to stop capturing in pre-sudo.log
    await removeSudoLogging();

    core.info(`🛡️ Starting Safer Runner Action in ${mode} mode`);
    if (mode === 'enforce' && blockRiskySubdomains) {
      core.info('🔒 Risky GitHub subdomain blocking: ENABLED');
    }

    // Check if pre-action already ran and set up infrastructure
    const preUsername = core.getState('dns-user');
    const preUid = core.getState('dns-uid');
    const preActionRan = preUsername && preUid;
    // Only trust the pre-hook's system-level work if it ran all the way through
    const preSetupCompleted = core.getState('pre-setup-completed') === 'true';

    let dnsUser: DnsUser;

    if (!preActionRan) {
      // Pre-action didn't run - do full setup
      core.info('Pre-action did not run - performing full setup...');
      dnsUser = await performInitialSetup();
    } else {
      // Pre-action already set up infrastructure - just reconfigure
      core.info('✅ Pre-action already established monitoring infrastructure');
      dnsUser = {
        username: preUsername,
        uid: parseInt(preUid, 10)
      };
    }

    // Setup rsyslog for main action iptables logs (separate from any pre-hook logs)
    core.info('Configuring iptables log filtering for main action...');
    await setupIptablesLogging(
      '/var/log/safer-runner/main-iptables.log',
      ['Main-GitHub-Allow', 'Main-User-Allow', 'Main-Drop-Enforce', 'Main-Allow-Analyze'],
      'main'
    );

    // Configure iptables rules with Main- log prefix.
    // The DNS servers MUST match the ones given to setupDNSMasq() below: the firewall only
    // permits DNS to the servers named here, so a mismatch drops every query dnsmasq makes.
    core.info('Configuring iptables rules...');
    await setupFirewallRules(dnsUser.uid, 'Main-', primaryDnsServer, secondaryDnsServer);

    // Configure DNS filtering
    core.info('Configuring DNS filtering...');
    await setupDNSConfig();

    // Configure DNSMasq
    core.info('Configuring DNSMasq...');
    const blockedSubdomains = await setupDNSMasq(
      mode,
      allowedDomains,
      blockRiskySubdomains,
      dnsUser.username,
      '/var/log/safer-runner/main-dns.log',
      primaryDnsServer,
      secondaryDnsServer
    );

    if (blockedSubdomains.length > 0) {
      core.info('🛡️ Blocking risky GitHub subdomains in enforce mode:');
      for (const subdomain of blockedSubdomains) {
        core.info(`  🚫 Blocked: ${subdomain}`);
      }
    }

    // Start services. systemd-resolved does not need restarting again when the pre-hook
    // already restarted it with identical configuration.
    core.info('Restarting services...');
    await restartServices('/var/log/safer-runner/main-dns.log', { skipResolvedRestart: preSetupCompleted });

    // Finalize firewall rules with Main- log prefix
    core.info('Finalizing firewall rules...');
    await finalizeFirewallRules(mode, 'Main-');

    // Capture post-setup baseline for integrity monitoring
    core.info('Capturing post-setup security baseline...');
    const validator = new SystemValidator();
    await validator.capturePostSetupBaseline();

    // Handle Docker configuration BEFORE disabling sudo (Docker operations require sudo)
    if (stopDocker) {
      core.info('Stopping Docker service completely...');
      await stopDockerService();
    } else if (disableDocker) {
      core.info('Disabling Docker access for runner user...');
      await disableDockerForRunner();
    }

    // Apply sudo configuration AFTER Docker is disabled
    // This must happen BEFORE setupSudoLogging() so that internal setup commands
    // are excluded from logs via Defaults!SAFER_RUNNER_CONFIG !log_allowed
    if (disableSudo) {
      core.info('Disabling sudo access for runner user...');
      await disableSudoForRunner();
    } else if (sudoConfig) {
      core.info('Applying custom sudo configuration...');
      await applyCustomSudoConfig(sudoConfig);
    } else {
      // No custom config - apply default config to set up exclusion rules
      core.info('Configuring default sudo access with validation exclusions...');
      await applyCustomSudoConfig();
    }

    // Setup sudo logging AFTER exclusion rules are in place
    // This ensures internal setup commands are not logged
    core.info('Configuring sudo logging for workflow monitoring...');
    await setupSudoLogging('/var/log/safer-runner/main-sudo.log');

    core.saveState('main-setup-completed', 'true');

    core.info(`✅ Safer Runner Action configured successfully in ${mode} mode`);
  } catch (error) {
    core.setFailed(`Action failed with error: ${error}`);
  }
}

run();
