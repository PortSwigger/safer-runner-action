jest.mock('@actions/core');
jest.mock('./setup');
jest.mock('./sudo');
jest.mock('./docker');
jest.mock('./validation');
jest.mock('./preflight');

const inputs: Record<string, string> = {};
const state: Record<string, string> = {};
let enabled = true;
let runnerSupported = true;

type Mocks = {
  setup: typeof import('./setup');
  core: typeof import('@actions/core');
  preflight: typeof import('./preflight');
};

/**
 * main.ts executes run() on import, so each scenario needs a fresh module registry -
 * otherwise the mock instances the assertions hold are not the ones main.ts imported.
 */
async function runMain(): Promise<Mocks> {
  let mocks!: Mocks;

  await jest.isolateModulesAsync(async () => {
    const core = await import('@actions/core');
    const setup = await import('./setup');
    const preflight = await import('./preflight');

    (core.getInput as jest.Mock).mockImplementation((n: string) => inputs[n] ?? '');
    (core.getBooleanInput as jest.Mock).mockImplementation(() => false);
    (core.getState as jest.Mock).mockImplementation((n: string) => state[n] ?? '');
    (setup.setupDNSMasq as jest.Mock).mockResolvedValue([]);
    (setup.performInitialSetup as jest.Mock).mockResolvedValue({ username: 'dns-x', uid: 1001 });
    // Supported runner unless a test says otherwise; preflight itself is covered in preflight.test.ts
    (preflight.isEnabled as jest.Mock).mockReturnValue(enabled);
    (preflight.assertRunnerSupported as jest.Mock).mockImplementation(async () => {
      if (!runnerSupported) throw new Error('this runner cannot support Safer Runner: no_new_privs');
    });

    mocks = { setup, core, preflight };

    await import('./main');
    // let the top-level async run() settle
    await new Promise(resolve => setImmediate(resolve));
  });

  return mocks;
}

describe('main.ts wiring', () => {
  beforeEach(() => {
    for (const k of Object.keys(inputs)) delete inputs[k];
    for (const k of Object.keys(state)) delete state[k];

    // pre-hook already ran and completed
    state['dns-user'] = 'dns-x';
    state['dns-uid'] = '1001';
    state['pre-setup-completed'] = 'true';
    enabled = true;
    runnerSupported = true;
  });

  it('gives the firewall the same DNS servers it gives dnsmasq', async () => {
    // Otherwise enforce mode drops the very DNS traffic dnsmasq is configured to send:
    // dnsmasq forwards to 1.1.1.1 while iptables only permits the Quad9 defaults.
    inputs['primary-dns-server'] = '1.1.1.1';
    inputs['secondary-dns-server'] = '1.0.0.1';
    inputs['mode'] = 'enforce';

    const { setup } = await runMain();

    expect(setup.setupFirewallRules).toHaveBeenCalledWith(1001, 'Main-', '1.1.1.1', '1.0.0.1');
  });

  it('defaults the firewall to Quad9 when no DNS servers are configured', async () => {
    const { setup } = await runMain();

    expect(setup.setupFirewallRules).toHaveBeenCalledWith(1001, 'Main-', '9.9.9.9', '149.112.112.112');
  });

  it('skips the redundant systemd-resolved restart when the pre-hook completed', async () => {
    const { setup } = await runMain();

    expect(setup.restartServices).toHaveBeenCalledWith('/var/log/safer-runner/main-dns.log', {
      skipResolvedRestart: true
    });
  });

  it('restarts systemd-resolved itself when the pre-hook did not complete', async () => {
    state['pre-setup-completed'] = '';

    const { setup } = await runMain();

    expect(setup.restartServices).toHaveBeenCalledWith('/var/log/safer-runner/main-dns.log', {
      skipResolvedRestart: false
    });
  });

  it('records that protection was established so the report can prove it', async () => {
    const { core } = await runMain();

    expect(core.saveState).toHaveBeenCalledWith('main-setup-completed', 'true');
    expect(core.setFailed).not.toHaveBeenCalled();
  });
});

describe('main.ts gating', () => {
  beforeEach(() => {
    for (const k of Object.keys(inputs)) delete inputs[k];
    for (const k of Object.keys(state)) delete state[k];
    enabled = true;
    runnerSupported = true;
  });

  it('does nothing at all when the action is disabled for this job', async () => {
    enabled = false;

    const { setup, core } = await runMain();

    expect(setup.performInitialSetup).not.toHaveBeenCalled();
    expect(core.setFailed).not.toHaveBeenCalled();
  });

  it('fails the job when protection was asked for but the runner cannot provide it', async () => {
    // The silent degradation this replaces is what let every self-hosted job run unprotected.
    runnerSupported = false;

    const { setup, core } = await runMain();

    expect(core.setFailed).toHaveBeenCalledWith(expect.stringContaining('cannot support Safer Runner'));
    expect(setup.performInitialSetup).not.toHaveBeenCalled();
  });

  it('checks the runner before touching the host', async () => {
    const { preflight, setup } = await runMain();

    expect(preflight.assertRunnerSupported).toHaveBeenCalled();
    expect(setup.setupFirewallRules).toHaveBeenCalled();
  });
});
