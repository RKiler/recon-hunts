#!/usr/bin/env node
// Open an owned verification link in the persistent visible browser, without logging it.
const { chromium } = require('/usr/local/lib/node_modules/playwright-core');

async function main() {
  let input = '';
  for await (const chunk of process.stdin) input += chunk;
  const { url, host } = JSON.parse(input);
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:' || parsed.hostname !== host || parsed.port) {
    throw new Error('Verification URL is outside the exact host');
  }
  const browser = await chromium.connectOverCDP('http://127.0.0.1:9222');
  const context = browser.contexts()[0];
  if (!context) throw new Error('Visible browser has no context');
  const page = context.pages().find(item => {
    try { return new URL(item.url()).hostname === host; } catch { return false; }
  }) || await context.newPage();
  let blockedRedirect = false;
  const routeHandler = async route => {
    const request = route.request();
    let permitted = false;
    try {
      const next = new URL(request.url());
      permitted = next.hostname === host && ['GET', 'HEAD', 'OPTIONS'].includes(request.method());
    } catch { /* reject malformed URL */ }
    if (!permitted) blockedRedirect = true;
    if (permitted) await route.continue();
    else await route.abort();
  };
  await page.route('**/*', routeHandler);
  let navigation = 'loaded';
  try { await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 20000 }); }
  catch { navigation = 'incomplete'; }
  finally { await page.unroute('**/*', routeHandler); }
  const finalHost = (() => { try { return new URL(page.url()).hostname; } catch { return ''; } })();
  process.stdout.write(JSON.stringify({ ok: true, navigation, final_host: finalHost,
    blocked_out_of_host_request: blockedRedirect }) + '\n');
}

main().then(() => process.exit(0)).catch(() => {
  process.stderr.write('Visible-browser verification failed\n');
  process.exit(1);
});
