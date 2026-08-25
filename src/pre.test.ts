jest.mock('@actions/core');
jest.mock('./setup');
jest.mock('./sudo');
jest.mock('./preflight');

let enabled = true;
let runnerSupported = true;

type Mocks = {
  setup: typeof import('./setup');
  core: typeof import('@actions/core');
  preflight: typeof import('./preflight');
};

/** pre.ts executes run() on import, so each scenario needs a fresh module registry. */
async function runPre(): Promise<Mocks> {
  let mocks!: Mocks;

  await jest.isolateModulesAsync(async () => {
    const core = await import('@actions/core');
    const setup = await import('./setup');
    const preflight = await import('./preflight');

    (core.getInput as jest.Mock).mockReturnValue('');
    (setup.performInitialSetup as jest.Mock).mockResolvedValue({ username: 'dns-x', uid: 1001 });
    (setup.setupDNSMasq as jest.Mock).mockResolvedValue([]);
    (preflight.isEnabled as jest.Mock).mockReturnValue(enabled);
    (preflight.assertRunnerSupported as jest.Mock).mockImplementation(async () => {
      if (!runnerSupported) {
        throw new Error("this runner cannot support Safer Runner: the kernel's no_new_privs bit is set");
      }
    });

    mocks = { setup, core, preflight };

    await import('./pre');
    // let the top-level async run() settle
    await new Promise(resolve => setImmediate(resolve));
  });

  return mocks;
}

describe('pre.ts gating', () => {
  beforeEach(() => {
    enabled = true;
    runnerSupported = true;
  });

  describe('when the job did not ask for protection', () => {
    // The hooks run regardless of the step's `if:`, because action.yaml has no pre-if and
    // GitHub defaults it to always(). Before this gate, every repository that never opted in
    // paid for three apt-get attempts and got a red annotation for its trouble.
    beforeEach(() => {
      enabled = false;
    });

    it('installs nothing', async () => {
      const { setup } = await runPre();

      expect(setup.performInitialSetup).not.toHaveBeenCalled();
    });

    it('stays silent rather than reporting a failure nobody asked about', async () => {
      const { core } = await runPre();

      expect(core.error).not.toHaveBeenCalled();
      expect(core.warning).not.toHaveBeenCalled();
    });

    it('does not probe the runner, because the answer would not change anything', async () => {
      const { preflight } = await runPre();

      expect(preflight.assertRunnerSupported).not.toHaveBeenCalled();
    });
  });

  describe('when the runner cannot support the action', () => {
    beforeEach(() => {
      runnerSupported = false;
    });

    it('reports why, naming the check that failed', async () => {
      const { core } = await runPre();

      expect(core.error).toHaveBeenCalledWith(expect.stringContaining('no_new_privs'));
    });

    it('gives up before installing anything, instead of retrying apt three times', async () => {
      const { setup } = await runPre();

      expect(setup.performInitialSetup).not.toHaveBeenCalled();
    });

    it('leaves no completion state, so the report cannot claim protection was applied', async () => {
      const { core } = await runPre();

      expect(core.saveState).not.toHaveBeenCalledWith('pre-setup-completed', 'true');
    });
  });

  describe('on a supported runner that asked for protection', () => {
    it('sets up monitoring as before', async () => {
      const { setup, core } = await runPre();

      expect(setup.performInitialSetup).toHaveBeenCalled();
      expect(core.saveState).toHaveBeenCalledWith('pre-setup-completed', 'true');
      expect(core.error).not.toHaveBeenCalled();
    });
  });
});
