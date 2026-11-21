/**
 * Run pa11y at WCAG 2 AAA over every page of the built site, in both colour schemes.
 *
 *   node tools/check-a11y.js [siteDir]        (default: ./site)
 *
 * The site is served from a throwaway local HTTP server so that the pages load
 * exactly as deployed (relative assets, instant navigation, the palette script).
 * The page list comes from the built sitemap.xml, so new pages are covered without
 * touching this file. EXTRA_PAGES adds the pages the sitemap leaves out, and STATES any
 * page state that only exists after interaction.
 * Each page is tested twice: once with the browser preferring a
 * light scheme and once preferring dark, because the theme follows that preference
 * and every colour pair differs between the two.
 *
 * Exit status is 1 if any page reports an error, or if a page could not be tested.
 *
 * Environment:
 *   CHROME_PATH       browser binary to use (default: the one puppeteer downloaded)
 *   A11Y_CONCURRENCY  pages tested in parallel (default: 4)
 *   A11Y_ONLY         substring filter on the page path, for local debugging
 */

"use strict";

const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const pa11y = require("pa11y");
const puppeteer = require("puppeteer");

const SITE = path.resolve(process.argv[2] || "site");
const STANDARD = "WCAG2AAA";
const CONCURRENCY = Number(process.env.A11Y_CONCURRENCY || 4);
const SCHEMES = [
  { name: "light", args: ["--blink-settings=preferredColorScheme=1"] },
  { name: "dark", args: ["--blink-settings=preferredColorScheme=0"] },
];
// Page states that only exist after interaction, as { path, name, actions } with pa11y
// actions; each entry is tested in addition to the plain page. None on this site yet.
const STATES = [];

// Built pages that are not in the sitemap but that readers do land on.
const EXTRA_PAGES = [{ path: "404.html", name: "page not found" }];

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json",
  ".xml": "application/xml",
  ".svg": "image/svg+xml",
  ".woff2": "font/woff2",
  ".png": "image/png",
};

// The site is served below the same path it is deployed under (the path part of
// the sitemap's URLs), because 404.html, which can be served for an address at any
// depth, refers to its stylesheets and scripts by absolute path. Served from "/",
// that page loaded unstyled and passed for the wrong reason.
function serve(root, basePath) {
  const server = http.createServer((request, response) => {
    const requested = decodeURIComponent(new URL(request.url, "http://x").pathname);
    if (!requested.startsWith(basePath)) {
      response.writeHead(404).end();
      return;
    }
    let file = path.join(root, requested.slice(basePath.length));
    if (!file.startsWith(root)) {
      response.writeHead(403).end();
      return;
    }
    if (fs.existsSync(file) && fs.statSync(file).isDirectory()) file = path.join(file, "index.html");
    fs.readFile(file, (error, body) => {
      if (error) {
        response.writeHead(404).end();
        return;
      }
      response.writeHead(200, { "Content-Type": TYPES[path.extname(file)] || "application/octet-stream" });
      response.end(body);
    });
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

function pagePaths(root) {
  const sitemap = fs.readFileSync(path.join(root, "sitemap.xml"), "utf8");
  const locations = [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) => match[1]);
  if (locations.length === 0) throw new Error("sitemap.xml lists no pages");
  // The sitemap carries the deployed URL; keep only the part below the site root.
  const base = locations.reduce((a, b) => (a.length <= b.length ? a : b));
  const pages = locations.map((loc) => ({ path: loc.slice(base.length) }));
  const known = new Set(pages.map((page) => page.path));
  for (const state of STATES) {
    if (!known.has(state.path.split("?")[0])) throw new Error(`STATES names a page the sitemap does not have: ${state.path}`);
  }
  for (const extra of EXTRA_PAGES) {
    if (!fs.existsSync(path.join(root, extra.path))) throw new Error(`EXTRA_PAGES names a file the build does not have: ${extra.path}`);
  }
  const only = process.env.A11Y_ONLY;
  return {
    basePath: new URL(base).pathname,
    paths: [...pages, ...EXTRA_PAGES, ...STATES].filter((page) => !only || page.path.includes(only)),
  };
}

async function runScheme(scheme, origin, paths) {
  const browser = await puppeteer.launch({
    executablePath: process.env.CHROME_PATH || undefined,
    args: ["--no-sandbox", ...scheme.args],
  });
  const failures = [];
  const queue = [...paths];
  async function worker() {
    for (let page = queue.shift(); page !== undefined; page = queue.shift()) {
      const label = `[${scheme.name}] /${page.path}${page.name ? ` (${page.name})` : ""}`;
      try {
        const result = await pa11y(`${origin}${page.path}`, {
          browser,
          standard: STANDARD,
          timeout: 60000,
          wait: 300,
          actions: page.actions || [],
        });
        const errors = result.issues.filter((issue) => issue.type === "error");
        for (const issue of errors) {
          failures.push(`${label}\n    ${issue.code}\n    ${issue.message}\n    ${issue.selector}`);
        }
        console.log(`${errors.length === 0 ? "ok  " : "FAIL"} ${label}${errors.length ? ` (${errors.length})` : ""}`);
      } catch (error) {
        failures.push(`${label}\n    could not be tested: ${error.message}`);
        console.log(`FAIL ${label} (not tested)`);
      }
    }
  }
  await Promise.all(Array.from({ length: CONCURRENCY }, worker));
  await browser.close();
  return failures;
}

async function main() {
  const { basePath, paths } = pagePaths(SITE);
  const server = await serve(SITE, basePath);
  const origin = `http://127.0.0.1:${server.address().port}${basePath}`;
  const failures = [];
  try {
    for (const scheme of SCHEMES) failures.push(...(await runScheme(scheme, origin, paths)));
  } finally {
    server.close();
  }
  if (failures.length > 0) {
    console.log(`\n${failures.join("\n\n")}`);
  }
  console.log(`\n${paths.length} page state(s) x ${SCHEMES.length} scheme(s) at ${STANDARD}: ${failures.length} error(s)`);
  process.exitCode = failures.length > 0 ? 1 : 0;
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
