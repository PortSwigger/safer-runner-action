import * as exec from '@actions/exec';
import { installDependencies } from './setup';

jest.mock('@actions/exec');
jest.mock('@actions/core');

type Captured = { program: string; args: string[] };

describe('installDependencies - apt hardening', () => {
  let captured: Captured[];

  /** Flatten a captured command back to a single string for easy assertions */
  const line = (c: Captured) => `${c.program} ${c.args.join(' ')}`;
  const aptUpdate = () => captured.filter(c => c.args.includes('update')).map(line);
  const aptInstall = () => captured.filter(c => c.args.includes('install')).map(line);
  /** Match on the whole command so tests do not care whether we shell out via sudo */
  const mentions = (c: Captured, needle: string) => line(c).includes(needle);

  beforeEach(() => {
    captured = [];
    jest.spyOn(exec, 'exec').mockImplementation(async (program, args) => {
      captured.push({ program, args: (args as string[]) || [] });
      return 0;
    });
  });

  afterEach(() => jest.restoreAllMocks());

  describe('unreachable-mirror protection (the 2026-08-19 hang)', () => {
    it('forces IPv4 so apt cannot pick an unreachable IPv6 mirror', async () => {
      await installDependencies();

      expect(aptUpdate()[0]).toContain('-o Acquire::ForceIPv4=true');
      expect(aptInstall()[0]).toContain('-o Acquire::ForceIPv4=true');
    });

    it('bounds each apt connection with an Acquire timeout', async () => {
      await installDependencies();

      expect(aptUpdate()[0]).toContain('-o Acquire::http::Timeout=');
      expect(aptUpdate()[0]).toContain('-o Acquire::https::Timeout=');
    });

    it('caps apt retries so a sick mirror cannot be retried ten times', async () => {
      await installDependencies();

      // The runner image ships APT::Acquire::Retries "10"; we must pin our own low value
      const retries = aptUpdate()[0].match(/-o Acquire::Retries=(\d+)/);
      expect(retries).not.toBeNull();
      expect(Number(retries![1])).toBeLessThanOrEqual(3);
    });

    it('runs every apt command under a hard wall-clock timeout', async () => {
      await installDependencies();

      // Without this, a blackholed SYN hangs the job until it is cancelled
      for (const cmd of [...aptUpdate(), ...aptInstall()]) {
        expect(cmd).toMatch(/\btimeout\b/);
      }
    });
  });

  describe('retry behaviour', () => {
    it('retries apt-get update when it fails, then succeeds', async () => {
      let updateAttempts = 0;
      jest.spyOn(exec, 'exec').mockImplementation(async (program, args) => {
        const a = (args as string[]) || [];
        captured.push({ program, args: a });
        if (a.includes('update')) {
          updateAttempts++;
          if (updateAttempts < 3) throw new Error('apt-get update failed with exit code 100');
        }
        return 0;
      });

      await installDependencies({ retryDelayMs: 0 });

      expect(updateAttempts).toBe(3);
      expect(aptInstall().length).toBe(1);
    });

    it('gives up after the attempt budget and throws', async () => {
      jest.spyOn(exec, 'exec').mockImplementation(async (program, args) => {
        const a = (args as string[]) || [];
        captured.push({ program, args: a });
        if (a.includes('update')) throw new Error('apt-get update failed with exit code 100');
        return 0;
      });

      await expect(installDependencies({ maxAttempts: 2, retryDelayMs: 0 })).rejects.toThrow(/apt-get update/);

      expect(aptUpdate().length).toBe(2);
      // must not attempt the install once update is known-broken
      expect(aptInstall().length).toBe(0);
    });
  });

  describe('verifying the packages actually arrived', () => {
    it('throws when dnsmasq and ipset are not installed afterwards', async () => {
      // Reproduces the real failure: update "succeeds" (exit 0 with only W: warnings),
      // install reports E: Unable to locate package, and setup must not continue silently.
      jest.spyOn(exec, 'exec').mockImplementation(async (program, args) => {
        const a = (args as string[]) || [];
        captured.push({ program, args: a });
        if (`${program} ${a.join(' ')}`.includes('dpkg-query')) return 1;
        return 0;
      });

      await expect(installDependencies({ retryDelayMs: 0 })).rejects.toThrow(/dnsmasq|ipset|not installed/i);
    });

    it('verifies both packages after a successful install', async () => {
      await installDependencies();

      const verify = captured.find(c => mentions(c, 'dpkg-query'));
      expect(verify).toBeDefined();
      expect(line(verify!)).toContain('dnsmasq');
      expect(line(verify!)).toContain('ipset');
    });
  });
});
