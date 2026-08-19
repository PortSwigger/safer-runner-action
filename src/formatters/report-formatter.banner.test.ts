import { generateSecurityStatusBanner } from './report-formatter';

describe('generateSecurityStatusBanner', () => {
  it('shows no banner when the main action established protection', () => {
    expect(generateSecurityStatusBanner({ preSetupCompleted: true, mainSetupCompleted: true, mode: 'enforce' })).toBe(
      ''
    );
  });

  it('raises a caution banner when no protection was established at all', () => {
    // The 2026-08-19 failure: apt could not install dnsmasq, pre.ts logged a warning, the main
    // step was skipped by the calling workflow, and the job ran completely unprotected.
    const banner = generateSecurityStatusBanner({
      preSetupCompleted: false,
      mainSetupCompleted: false,
      mode: 'enforce',
      preSetupError: 'apt-get update failed after 3 attempts'
    });

    expect(banner).toContain('[!CAUTION]');
    expect(banner).toMatch(/no network protection/i);
    expect(banner).toContain('apt-get update failed after 3 attempts');
  });

  it('warns when the pre-hook monitored but the configured mode was never applied', () => {
    const banner = generateSecurityStatusBanner({
      preSetupCompleted: true,
      mainSetupCompleted: false,
      mode: 'enforce'
    });

    expect(banner).toContain('[!WARNING]');
    expect(banner).toMatch(/enforce/);
    expect(banner).toMatch(/was not applied|never applied/i);
    expect(banner).not.toContain('[!CAUTION]');
  });

  it('does not claim enforcement was active when it was not', () => {
    const banner = generateSecurityStatusBanner({
      preSetupCompleted: false,
      mainSetupCompleted: false,
      mode: 'analyze'
    });

    expect(banner).toMatch(/unprotected|no network protection/i);
  });
});
