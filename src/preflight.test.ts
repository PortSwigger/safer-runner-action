import * as core from '@actions/core';
import * as exec from '@actions/exec';
import * as fs from 'fs';
import {
  assertRunnerSupported,
  canSudoNonInteractively,
  checkRunnerSupport,
  hasNoNewPrivs,
  hasSystemd,
  isEnabled,
  parseMode,
  describeMode,
  warnIfRunnerUnsupported
} from './preflight';

jest.mock('@actions/exec');
jest.mock('@actions/core');
// Partial mock: @actions/io reads fs.promises at import time, so the real module must survive.
jest.mock('fs', () => ({
  ...jest.requireActual('fs'),
  readFileSync: jest.fn(),
  existsSync: jest.fn()
}));

const readFileSync = fs.readFileSync as jest.Mock;
const existsSync = fs.existsSync as jest.Mock;
const execMock = exec.exec as jest.Mock;

/** Shape the three probes independently so each scenario reads as the runner it describes. */
function runner(opts: { noNewPrivs?: boolean; systemd?: boolean; sudo?: boolean }) {
  readFileSync.mockReturnValue(`Name:\tnode\nNoNewPrivs:\t${opts.noNewPrivs ? 1 : 0}\nSeccomp:\t0\n`);
  existsSync.mockReturnValue(opts.systemd ?? true);
  execMock.mockResolvedValue(opts.sudo === false ? 1 : 0);
}

const githubHosted = () => runner({ noNewPrivs: false, systemd: true, sudo: true });
const arcPod = () => runner({ noNewPrivs: true, systemd: false, sudo: false });

beforeEach(() => jest.resetAllMocks());

describe('isEnabled', () => {
  it('defaults to enabled when the input is absent', () => {
    expect(isEnabled('')).toBe(true);
  });

  it.each(['false', 'FALSE', '  False  '])('treats %p as disabled', value => {
    expect(isEnabled(value)).toBe(false);
  });

  it('does not treat an unrelated value as disabled, so a typo cannot silently drop protection', () => {
    expect(isEnabled('no')).toBe(true);
    expect(isEnabled('0')).toBe(true);
  });

  it('warns on a value that is neither true nor false, so `enabled: no` is not silent', () => {
    // Whoever writes `enabled: no` is reaching for this input because something is already
    // wrong on their runner. Treating it as true is safe; saying nothing is not helpful.
    expect(isEnabled('no')).toBe(true);
    expect(core.warning).toHaveBeenCalledWith(expect.stringContaining('must be true or false'));
  });

  it('says nothing for the values it documents', () => {
    isEnabled('true');
    isEnabled('false');
    isEnabled('');
    expect(core.warning).not.toHaveBeenCalled();
  });
});

describe('hasNoNewPrivs', () => {
  it('reads the bit from /proc/self/status', () => {
    runner({ noNewPrivs: true });
    expect(hasNoNewPrivs()).toBe(true);
    expect(fs.readFileSync).toHaveBeenCalledWith('/proc/self/status', 'utf8');
  });

  it('is false when the bit is clear', () => {
    runner({ noNewPrivs: false });
    expect(hasNoNewPrivs()).toBe(false);
  });

  it('assumes the bit is clear when /proc is unreadable, rather than refusing a working host', () => {
    readFileSync.mockImplementation(() => {
      throw new Error('ENOENT');
    });
    expect(hasNoNewPrivs()).toBe(false);
  });
});

describe('hasSystemd', () => {
  it('detects systemd from its runtime directory', () => {
    existsSync.mockReturnValue(true);
    expect(hasSystemd()).toBe(true);
    expect(fs.existsSync).toHaveBeenCalledWith('/run/systemd/system');
  });

  it('is false in a container with no init system', () => {
    existsSync.mockReturnValue(false);
    expect(hasSystemd()).toBe(false);
  });
});

describe('canSudoNonInteractively', () => {
  it('probes without a password prompt so it cannot hang', async () => {
    execMock.mockResolvedValue(0);

    await expect(canSudoNonInteractively()).resolves.toBe(true);
    expect(exec.exec).toHaveBeenCalledWith('sudo', ['-n', 'true'], expect.objectContaining({ ignoreReturnCode: true }));
  });

  it('is false when sudo exits non-zero', async () => {
    execMock.mockResolvedValue(1);
    await expect(canSudoNonInteractively()).resolves.toBe(false);
  });
});

describe('checkRunnerSupport', () => {
  it('supports a GitHub-hosted runner', async () => {
    githubHosted();
    await expect(checkRunnerSupport()).resolves.toEqual({ supported: true, reasons: [] });
  });

  it('rejects an ARC pod, naming allowPrivilegeEscalation so the fix is obvious', async () => {
    arcPod();

    const { supported, reasons } = await checkRunnerSupport();

    expect(supported).toBe(false);
    expect(reasons.join(' ')).toContain('no_new_privs');
    expect(reasons.join(' ')).toContain('allowPrivilegeEscalation');
    expect(reasons.join(' ')).toContain('systemd');
  });

  it('does not also blame sudo when no_new_privs already explains it', async () => {
    runner({ noNewPrivs: true, systemd: true, sudo: false });

    const { reasons } = await checkRunnerSupport();

    expect(reasons).toHaveLength(1);
    expect(exec.exec).not.toHaveBeenCalled();
  });

  it('reports a missing sudoers entry on a host that is otherwise fine', async () => {
    runner({ noNewPrivs: false, systemd: true, sudo: false });

    const { supported, reasons } = await checkRunnerSupport();

    expect(supported).toBe(false);
    expect(reasons).toEqual(['the runner user cannot run sudo without a password']);
  });
});

describe('assertRunnerSupported', () => {
  it('resolves on a supported runner', async () => {
    githubHosted();
    await expect(assertRunnerSupported()).resolves.toBeUndefined();
  });

  it('throws with the reasons and the way out', async () => {
    arcPod();

    await expect(assertRunnerSupported()).rejects.toThrow(/cannot support Safer Runner/);
    await expect(assertRunnerSupported()).rejects.toThrow(/enabled: false/);
  });
});

describe('warnIfRunnerUnsupported', () => {
  it('warns without throwing, so a wrong answer cannot fail a job that would have worked', async () => {
    arcPod();

    await expect(warnIfRunnerUnsupported()).resolves.toBe(false);
    expect(core.warning).toHaveBeenCalledWith(expect.stringContaining('Attempting setup anyway'));
  });

  it('says nothing on a supported runner', async () => {
    githubHosted();

    await expect(warnIfRunnerUnsupported()).resolves.toBe(true);
    expect(core.warning).not.toHaveBeenCalled();
  });
});

describe('parseMode', () => {
  it.each(['analyze', 'enforce'])('accepts %p', value => {
    expect(parseMode(value)).toBe(value);
  });

  it('falls back to the documented default when empty, which applies monitoring rather than removing it', () => {
    expect(parseMode('')).toBe('analyze');
  });

  it("normalises case, because 'Enforce' silently meant analyze while the report said Enforce", () => {
    // Every mode comparison in the codebase is a strict === 'enforce', so a capitalised value
    // used to produce analyze behaviour under a summary claiming enforcement.
    expect(parseMode('Enforce')).toBe('enforce');
    expect(parseMode('  ANALYZE ')).toBe('analyze');
  });

  it('rejects anything else rather than quietly picking a mode the caller did not ask for', () => {
    expect(() => parseMode('enforc')).toThrow(/must be 'analyze' or 'enforce', but was 'enforc'/);
    expect(() => parseMode('block')).toThrow(/must be 'analyze' or 'enforce'/);
  });
});

describe('describeMode', () => {
  it('normalises for the report so the summary matches what was applied', () => {
    expect(describeMode('Enforce')).toBe('enforce');
  });

  it('still renders an invalid mode rather than throwing inside the report', () => {
    expect(describeMode('nonsense')).toBe('nonsense');
  });
});
