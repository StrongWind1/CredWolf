/**
 * Fail unless a built site is present.
 *
 *   node tools/require-site.js [siteDir]        (default: ./site)
 *
 * The Nu HTML Checker exits 0 when the directory it is given does not exist, so
 * without this guard "no site" would read as "no problems". Run `make docs` first.
 */

"use strict";

const fs = require("node:fs");
const path = require("node:path");

const site = path.resolve(process.argv[2] || "site");
const required = ["index.html", "sitemap.xml"].map((name) => path.join(site, name));
const missing = required.filter((file) => !fs.existsSync(file));

if (missing.length > 0) {
  console.error(`No built site at ${site} (missing ${missing.map((file) => path.basename(file)).join(", ")}). Run \`make docs\` first.`);
  process.exitCode = 1;
}
