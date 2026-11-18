const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { chromium } = require('/usr/local/lib/node_modules/playwright-core');

const makeSession = `import hashlib, os, yaml
from flask import Flask
from flask.sessions import SecureCookieSessionInterface
config = yaml.safe_load(open('/app/config.yaml'))
app = Flask(__name__)
password = str(os.getenv('RECON_DASHBOARD_PASSWORD') or config.get('dashboard', {}).get('auth', {}).get('password') or '')
app.secret_key = hashlib.sha256(f'recon-dashboard-session:{password}'.encode()).digest()
print(SecureCookieSessionInterface().get_signing_serializer(app).dumps({
    'recon_dashboard_authenticated': True,
    'recon_dashboard_csrf': 'a' * 32,
}))`;

(async () => {
  const session = spawnSync('python3', ['-c', makeSession], { encoding: 'utf8' });
  if (session.status !== 0) throw new Error(`Session setup failed: ${session.stderr.trim()}`);
  const browser = await chromium.launch({ executablePath: '/usr/bin/chromium', headless: true, args: ['--no-sandbox'] });
  try {
    const context = await browser.newContext();
    await context.addCookies([{
      name: 'recon_dashboard_session', value: session.stdout.trim(),
      url: 'http://dashboard:5000', httpOnly: true, sameSite: 'Lax',
    }]);
    const page = await context.newPage();
    const response = await page.goto('http://dashboard:5000/agentic?domain_id=5');
    assert.equal(response.status(), 200);
    await page.getByRole('button', { name: 'Details' }).first().waitFor({ timeout: 10000 }).catch(async () => {
      throw new Error(`No lead rows at ${page.url()}: ${(await page.locator('body').innerText()).slice(0, 450)}`);
    });
    await page.getByRole('button', { name: 'Details' }).first().click();
    await page.locator('#leadDetail .lead-detail-list').waitFor();
    assert.match(await page.locator('#leadDetail').innerText(), /Source Record/i);
    assert.match(await page.locator('#leadDetail').innerText(), /Prior assessment|Run conclusion/);
    await page.getByRole('button', { name: 'Add account for this host' }).click();
    assert.equal(await page.locator('#accountHost').inputValue(), 'sidekick.zapier.com');
    assert.equal(await page.locator('#accountManager').evaluate((node) => node.open), true);
    let accountPosted = null;
    await page.route('**/api/hunt-credentials', async (route) => {
      if (route.request().method() !== 'POST') return route.continue();
      accountPosted = JSON.parse(route.request().postData());
      await route.fulfill({ status: 201, contentType: 'application/json',
        body: JSON.stringify({ id: 999998, alias: accountPosted.alias, host: accountPosted.host }) });
    });
    await page.locator('#accountAlias').fill('sidekick-owner-test');
    await page.locator('#accountEmail').fill('owner@example.com');
    await page.locator('#accountPassword').fill('owned-test-password');
    await page.locator('#accountAuthorized').check();
    await page.getByRole('button', { name: 'Add account', exact: true }).click();
    assert.equal(accountPosted.host, 'sidekick.zapier.com');
    assert.equal(accountPosted.credential_type, 'login_file');
    assert.equal(accountPosted.email, 'owner@example.com');
    assert.equal(accountPosted.password, 'owned-test-password');
    assert.equal(accountPosted.authorized, true);
    await page.locator('#accountAlias').fill('sidekick-manual-test');
    await page.locator('#accountType').selectOption('manual_login');
    await page.locator('#accountAuthorized').check();
    await page.getByRole('button', { name: 'Add account', exact: true }).click();
    assert.equal(accountPosted.credential_type, 'manual_login');
    assert.equal(accountPosted.secret, '');
    await page.getByRole('button', { name: 'Details' }).first().click();
    await page.locator('#leadDetail .lead-detail-list').waitFor();
    await page.setViewportSize({ width: 390, height: 844 });
    const dialogBounds = await page.locator('#leadDialog').boundingBox();
    assert.ok(dialogBounds.x >= 0 && dialogBounds.x + dialogBounds.width <= 390);
    assert.ok(dialogBounds.y >= 0 && dialogBounds.y + dialogBounds.height <= 844);
    await page.getByRole('button', { name: 'Queue validation' }).click();
    assert.match(await page.locator('#leadMessage').innerText(), /Confirm this exact host/);

    let posted = null;
    await page.route('**/api/agentic/runs', async (route) => {
      if (route.request().method() !== 'POST') return route.continue();
      posted = JSON.parse(route.request().postData());
      await route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify({ id: 999999, status: 'queued' }) });
    });
    await page.locator('#leadScopeConfirmed').check();
    await page.getByRole('button', { name: 'Queue validation' }).click();
    await page.waitForFunction(() => !document.querySelector('#leadDialog').open);
    assert.equal(posted.action, 'validate');
    assert.equal(posted.scope_confirmed, true);
    assert.equal(posted.domain_id, 5);
    assert.ok(Number.isInteger(posted.lead_id));
    console.log('Agentic lead details and Validate UI smoke test passed');
  } finally {
    await browser.close();
  }
})().catch((error) => { console.error(error); process.exitCode = 1; });
