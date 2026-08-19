import * as exec from '@actions/exec';
import { buildOutputRules, buildTerminalRules, setupFirewallRules, finalizeFirewallRules } from './setup';
import { DEFAULT_DNS_SERVER, SECONDARY_DNS_SERVER } from './config/dns-config-builder';

jest.mock('@actions/exec');
jest.mock('@actions/core');

type Captured = { program: string; args: string[]; input?: string };

describe('firewall rules are applied in one batch', () => {
  let captured: Captured[];

  const restoreCalls = () => captured.filter(c => c.args.includes('iptables-restore'));
  const restorePayload = () =>
    restoreCalls()
      .map(c => c.input || '')
      .join('\n');

  beforeEach(() => {
    captured = [];
    jest.spyOn(exec, 'exec').mockImplementation(async (program, args, options) => {
      captured.push({
        program,
        args: (args as string[]) || [],
        input: options?.input ? options.input.toString() : undefined
      });
      return 0;
    });
  });

  afterEach(() => jest.restoreAllMocks());

  describe('buildOutputRules', () => {
    const rules = (secondary: string = SECONDARY_DNS_SERVER) =>
      buildOutputRules({
        dnsUid: 1001,
        logPrefix: 'Main-',
        primaryDnsServer: DEFAULT_DNS_SERVER,
        secondaryDnsServer: secondary
      });

    it('allows established connections first', () => {
      expect(rules()[0]).toBe('-A OUTPUT -o eth0 -m conntrack --ctstate ESTABLISHED -j ACCEPT');
    });

    it('allows both Azure metadata addresses', () => {
      expect(rules()).toContain('-A OUTPUT -o eth0 -d 168.63.129.16 -j ACCEPT');
      expect(rules()).toContain('-A OUTPUT -o eth0 -d 169.254.169.254 -j ACCEPT');
    });

    it('quotes the log prefix so its trailing space survives iptables-restore parsing', () => {
      // An unquoted "--log-prefix=Main-GitHub-Allow: " loses the trailing space and the
      // rsyslog filter stops matching, silently emptying the report.
      expect(rules()).toContain(
        '-A OUTPUT -o eth0 -m set --match-set github dst -j LOG --log-prefix "Main-GitHub-Allow: "'
      );
      expect(rules()).toContain(
        '-A OUTPUT -o eth0 -m set --match-set user dst -j LOG --log-prefix "Main-User-Allow: "'
      );
    });

    it('accepts traffic matching the github and user ipsets', () => {
      expect(rules()).toContain('-A OUTPUT -o eth0 -m set --match-set github dst -j ACCEPT');
      expect(rules()).toContain('-A OUTPUT -o eth0 -m set --match-set user dst -j ACCEPT');
    });

    it('logs an ipset match before accepting it', () => {
      const r = rules();
      expect(
        r.indexOf('-A OUTPUT -o eth0 -m set --match-set github dst -j LOG --log-prefix "Main-GitHub-Allow: "')
      ).toBeLessThan(r.indexOf('-A OUTPUT -o eth0 -m set --match-set github dst -j ACCEPT'));
    });

    it('permits DNS to the configured servers only from the dnsmasq uid', () => {
      expect(rules()).toContain(
        `-A OUTPUT -o eth0 -d ${DEFAULT_DNS_SERVER} -p udp --dport 53 -m owner --uid-owner 1001 -j ACCEPT`
      );
      expect(rules()).toContain(
        `-A OUTPUT -o eth0 -d ${SECONDARY_DNS_SERVER} -p udp --dport 53 -m owner --uid-owner 1001 -j ACCEPT`
      );
    });

    it('silently drops ICMP destination-unreachable to the DNS servers', () => {
      expect(rules()).toContain(
        `-A OUTPUT -o eth0 -d ${DEFAULT_DNS_SERVER} -p icmp --icmp-type destination-unreachable -j DROP`
      );
      expect(rules()).toContain(
        `-A OUTPUT -o eth0 -d ${SECONDARY_DNS_SERVER} -p icmp --icmp-type destination-unreachable -j DROP`
      );
    });

    it('honours custom DNS servers for both the allow and ICMP rules', () => {
      const r = buildOutputRules({
        dnsUid: 1001,
        logPrefix: 'Main-',
        primaryDnsServer: '8.8.8.8',
        secondaryDnsServer: '8.8.4.4'
      });

      expect(r).toContain('-A OUTPUT -o eth0 -d 8.8.8.8 -p udp --dport 53 -m owner --uid-owner 1001 -j ACCEPT');
      expect(r).toContain('-A OUTPUT -o eth0 -d 8.8.4.4 -p udp --dport 53 -m owner --uid-owner 1001 -j ACCEPT');
      expect(r).toContain('-A OUTPUT -o eth0 -d 8.8.8.8 -p icmp --icmp-type destination-unreachable -j DROP');
      expect(r).toContain('-A OUTPUT -o eth0 -d 8.8.4.4 -p icmp --icmp-type destination-unreachable -j DROP');
      expect(r.filter(l => l.includes(DEFAULT_DNS_SERVER))).toHaveLength(0);
    });

    it('omits secondary DNS rules when no secondary server is configured', () => {
      const r = rules('');
      expect(r.filter(l => l.includes(SECONDARY_DNS_SERVER))).toHaveLength(0);
      expect(r.filter(l => l.includes('icmp'))).toHaveLength(1);
    });
  });

  describe('buildTerminalRules', () => {
    it('logs then drops in enforce mode', () => {
      expect(buildTerminalRules('enforce', 'Main-')).toEqual([
        '-A OUTPUT -o eth0 -j LOG --log-prefix "Main-Drop-Enforce: "',
        '-A OUTPUT -o eth0 -j DROP'
      ]);
    });

    it('handles an empty log prefix', () => {
      expect(buildTerminalRules('enforce', '')).toContain('-A OUTPUT -o eth0 -j LOG --log-prefix "Drop-Enforce: "');
      expect(buildTerminalRules('analyze', '')).toContain('-A OUTPUT -o eth0 -j LOG --log-prefix "Allow-Analyze: "');
    });

    it('logs then accepts in analyze mode', () => {
      expect(buildTerminalRules('analyze', 'Pre-')).toEqual([
        '-A OUTPUT -o eth0 -j LOG --log-prefix "Pre-Allow-Analyze: "',
        '-A OUTPUT -o eth0 -j ACCEPT'
      ]);
    });
  });

  describe('setupFirewallRules', () => {
    it('flushes only the OUTPUT chain, leaving INPUT and FORWARD intact', async () => {
      await setupFirewallRules(1001, 'Main-');

      expect(captured[0].args).toEqual(['iptables', '-F', 'OUTPUT']);
      // a bare `iptables-restore` (no --noflush) would wipe INPUT/FORWARD, which
      // validation.ts baselines and would report as tampering
      expect(restoreCalls().every(c => c.args.includes('--noflush'))).toBe(true);
    });

    it('applies every rule in a single iptables-restore call', async () => {
      await setupFirewallRules(1001, 'Main-');

      expect(restoreCalls()).toHaveLength(1);
      // one flush + one restore, instead of ~20 separate sudo iptables spawns
      expect(captured).toHaveLength(2);
    });

    it('feeds iptables-restore a well formed filter table', async () => {
      await setupFirewallRules(1001, 'Main-');

      const payload = restorePayload();
      expect(payload.startsWith('*filter\n')).toBe(true);
      expect(payload.trimEnd().endsWith('COMMIT')).toBe(true);
      expect(payload).toContain('-A OUTPUT -o eth0 -m conntrack --ctstate ESTABLISHED -j ACCEPT');
    });
  });

  describe('finalizeFirewallRules', () => {
    it('appends the terminal rules in one restore call without flushing', async () => {
      await finalizeFirewallRules('enforce', 'Main-');

      expect(restoreCalls()).toHaveLength(1);
      expect(restoreCalls()[0].args).toContain('--noflush');
      expect(restorePayload()).toContain('-A OUTPUT -o eth0 -j DROP');
      // must not re-flush: the rules from setupFirewallRules have to survive
      expect(captured.some(c => c.args.includes('-F'))).toBe(false);
    });
  });
});
