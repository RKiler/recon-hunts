#!/usr/bin/env node
// Read-only, one-page browser evidence capture for independent domain hunts.
const fs = require('fs');
const path = require('path');
const { chromium } = require('/usr/local/lib/node_modules/playwright-core');

function argumentsMap(argv) {
  const result = { exclude: [] };
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i];
    if (!key.startsWith('--') || !argv[i + 1]) throw new Error(`Invalid argument ${key}`);
    if (key === '--exclude') result.exclude.push(argv[i + 1].toLowerCase());
    else result[key.slice(2)] = argv[i + 1];
  }
  return result;
}

function allowed(url, root, subdomains, exclusions) {
  let parsed;
  try { parsed = new URL(url); } catch { return false; }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) return false;
  const host = parsed.hostname.toLowerCase();
  if (!(host === root || (subdomains && host.endsWith(`.${root}`)))) return false;
  return !exclusions.some(item => host === item || host.endsWith(`.${item}`));
}

function display(url) {
  try {
    const parsed = new URL(url);
    return `${parsed.origin}${parsed.pathname.slice(0, 300)}`;
  } catch { return '[invalid URL]'; }
}

async function capture(options) {
  const root = (options['root-domain'] || '').toLowerCase();
  const target = options.url || '';
  const output = options.output || '';
  const subdomains = options['include-subdomains'] === 'true';
  const exclusions = options.exclude || [];
  if (!root || !output || !allowed(target, root, subdomains, exclusions)) {
    throw new Error('Target, root domain, or output missing or target out of scope');
  }
  if (options['storage-state'] && options['session-host'] !== new URL(target).hostname) {
    throw new Error('Authenticated capture requires an exact matching session host');
  }
  const requests = [];
  const scripts = [];
  let permittedCount = 0;
  let blockedCount = 0;
  const browser = await chromium.launch({ executablePath: '/usr/bin/chromium', headless: true,
    args: ['--no-sandbox', '--disable-dev-shm-usage'] });
  try {
    const context = await browser.newContext({ storageState: options['storage-state'] || undefined,
      proxy: options.proxy ? { server: options.proxy } : undefined,
      acceptDownloads: false, serviceWorkers: 'block' });
    const page = await context.newPage();
    await page.route('**/*', async route => {
      const request = route.request();
      const url = request.url();
      const method = request.method();
      const scopeOk = allowed(url, root, subdomains, exclusions);
      const permit = scopeOk && ['GET', 'HEAD', 'OPTIONS'].includes(method) && permittedCount < 60;
      if (permit) permittedCount += 1;
      else blockedCount += 1;
      if (scopeOk && requests.length < 100) {
        requests.push({ method, url: display(url), resource_type: request.resourceType(),
          allowed: permit });
      }
      if (permit) await route.continue();
      else await route.abort();
    });
    page.on('response', response => {
      const request = response.request();
      if (request.resourceType() === 'script' && scripts.length < 80) {
        scripts.push({ url: display(response.url()), status: response.status() });
      }
    });
    let navigationError = null;
    try { await page.goto(target, { waitUntil: 'domcontentloaded', timeout: 20000 }); }
    catch (error) { navigationError = String(error.name || 'NavigationError').slice(0, 80); }
    await page.waitForTimeout(1000);
    const finalUrl = page.url();
    const stillInScope = allowed(finalUrl, root, subdomains, exclusions);
    const pageData = stillInScope ? await page.evaluate(() => ({
      title: document.title.slice(0, 140),
      forms: Array.from(document.forms).slice(0, 20).map(form => ({
        method: (form.getAttribute('method') || 'GET').toUpperCase(),
        action: form.getAttribute('action') || '',
        fields: Array.from(form.elements).slice(0, 30).map(element => ({
          name: element.name || '', type: element.type || ''
        }))
      })),
      links: Array.from(document.querySelectorAll('a[href]')).slice(0, 60)
        .map(link => link.href),
    })) : { title: '', forms: [], links: [] };
    const sanitizedLinks = pageData.links.filter(url => allowed(url, root, subdomains, exclusions))
      .map(display);
    const forms = pageData.forms.map(form => ({ ...form,
      action: form.action ? display(new URL(form.action, finalUrl).href) : display(finalUrl) }));
    const result = { target: display(target), final_url: display(finalUrl), in_scope: stillInScope,
      navigation_error: navigationError, title: pageData.title,
      permitted_request_count: permittedCount, blocked_request_count: blockedCount,
      requests, scripts, forms, links: [...new Set(sanitizedLinks)] };
    fs.mkdirSync(path.dirname(output), { recursive: true, mode: 0o700 });
    fs.writeFileSync(output, JSON.stringify(result, null, 2), { mode: 0o600 });
    console.log(JSON.stringify({ output, in_scope: stillInScope,
      permitted_request_count: permittedCount, blocked_request_count: blockedCount }));
    await context.close();
  } finally { await browser.close(); }
}

if (require.main === module) {
  capture(argumentsMap(process.argv.slice(2))).catch(error => {
    console.error(String(error.message).slice(0, 300));
    process.exitCode = 1;
  });
}
module.exports = { allowed, display, argumentsMap, capture };
