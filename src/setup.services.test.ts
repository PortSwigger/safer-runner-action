import * as exec from '@actions/exec';
import * as fs from 'fs';
import { restartServices } from './setup';

jest.mock('@actions/exec');
jest.mock('@actions/core');
// Partial mock: @actions/io needs the real fs.promises, we only want to control existsSync
jest.mock('fs', () => ({ ...jest.requireActual('fs'), existsSync: jest.fn() }));

const existsSyncMock = fs.existsSync as jest.MockedFunction<typeof fs.existsSync>;

describe('restartServices', () => {
  let captured: Array<{ program: string; args: string[] }>;
  const line = (c: { program: string; args: string[] }) => `${c.program} ${c.args.join(' ')}`;

  beforeEach(() => {
    captured = [];
    jest.spyOn(exec, 'exec').mockImplementation(async (program, args) => {
      captured.push({ program, args: (args as string[]) || [] });
      return 0;
    });
  });

  afterEach(() => {
    jest.restoreAllMocks();
    existsSyncMock.mockReset();
  });

  it('restarts systemd-resolved and dnsmasq', async () => {
    existsSyncMock.mockReturnValue(true);

    await restartServices();

    expect(captured.map(line)).toEqual(['sudo systemctl restart systemd-resolved', 'sudo systemctl restart dnsmasq']);
  });

  it('waits for dnsmasq to create the log file before chmodding it', async () => {
    // dnsmasq creates the file as 0640; the chmod is what lets the runner read it without sudo.
    // A fixed sleep either wastes time or fires too early and the chmod fails on a missing file.
    let checks = 0;
    existsSyncMock.mockImplementation(() => ++checks >= 3);

    await restartServices('/var/log/safer-runner/main-dns.log', { pollIntervalMs: 0 });

    expect(checks).toBe(3);
    expect(captured.map(line)).toContain('sudo chmod 0644 /var/log/safer-runner/main-dns.log');
  });

  it('chmods immediately when the log file already exists', async () => {
    const existsSync = existsSyncMock.mockReturnValue(true);

    await restartServices('/var/log/safer-runner/main-dns.log', { pollIntervalMs: 0 });

    expect(existsSyncMock).toHaveBeenCalledTimes(1);
  });

  it('warns instead of failing setup when the log file never appears', async () => {
    existsSyncMock.mockReturnValue(false);

    await expect(
      restartServices('/var/log/safer-runner/main-dns.log', { pollIntervalMs: 0, logFileTimeoutMs: 5 })
    ).resolves.toBeUndefined();

    // chmod on a missing file exits non-zero, which would abort the whole setup
    expect(captured.map(line).some(c => c.includes('chmod'))).toBe(false);
  });

  it('skips the systemd-resolved restart when the pre-hook already did it', async () => {
    existsSyncMock.mockReturnValue(true);

    await restartServices(undefined, { skipResolvedRestart: true });

    expect(captured.map(line)).toEqual(['sudo systemctl restart dnsmasq']);
  });
});
