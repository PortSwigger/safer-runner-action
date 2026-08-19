jest.mock('@actions/core');
jest.mock('./setup');
jest.mock('./sudo');
jest.mock('./docker');
jest.mock('./validation');

const inputs: Record<string, string> = {};
const state: Record<string, string> = {};

type Mocks = {
  setup: typeof import('./setup');
  core: typeof import('@actions/core');
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

    (core.getInput as jest.Mock).mockImplementation((n: string) => inputs[n] ?? '');
    (core.getBooleanInput as jest.Mock).mockImplementation(() => false);
    (core.getState as jest.Mock).mockImplementation((n: string) => state[n] ?? '');
    (setup.setupDNSMasq as jest.Mock).mockResolvedValue([]);
    (setup.performInitialSetup as jest.Mock).mockResolvedValue({ username: 'dns-x', uid: 1001 });

    mocks = { setup, core };

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
