import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { stripTypeScriptTypes } from "node:module";
import { extname, join, normalize } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { chromium, firefox, webkit } from "playwright-core";

// The package in Chromium, Firefox and WebKit through Playwright (a test-only tool): the built
// dist/ runs synchronously on the main thread with each backend, and pages whose content security
// policy forbids WebAssembly compilation prove the fallback to TypeScript. Usage, after npm run
// build: node test/browser/runner.ts. Prints one line per browser and page; exits with status 1 if
// any differs from what it expects.

const PACKAGE = fileURLToPath(new URL("../../", import.meta.url));

const PAGE = stripTypeScriptTypes(readFileSync(new URL("./page.ts", import.meta.url), "utf8"));

// Each page's content security policy, if any, and what it expects of every family.
const PAGES: [string, string | null, string][] = [
  ["auto", null, "wasm"],
  ["wasm", null, "wasm"],
  ["js", null, "js"],
  ["auto", "script-src 'self'", "js"],
  ["wasm", "script-src 'self'", "UNSUPPORTED"],
  ["auto", "script-src 'self' 'wasm-unsafe-eval'", "wasm"],
];

const TYPES: Record<string, string> = { ".js": "text/javascript", ".html": "text/html" };

const server = createServer((request, response) => {
  const url = new URL(request.url ?? "/", "http://localhost");

  const csp = url.searchParams.get("csp");

  const headers: Record<string, string> = csp === null ? {} : { "Content-Security-Policy": csp };

  if (url.pathname === "/page.html") {
    response.writeHead(200, { ...headers, "Content-Type": TYPES[".html"] });

    response.end('<!doctype html><meta charset="utf-8"><pre id="out">not run</pre><script type="module" src="/page.js"></script>');
  } else if (url.pathname === "/page.js") {
    response.writeHead(200, { ...headers, "Content-Type": TYPES[".js"] });

    response.end(PAGE);
  } else if (url.pathname.startsWith("/dist/") && extname(url.pathname) === ".js") {
    const path = normalize(join(PACKAGE, url.pathname));

    if (!path.startsWith(join(PACKAGE, "dist"))) {
      response.writeHead(403).end();

      return;
    }

    response.writeHead(200, { ...headers, "Content-Type": TYPES[".js"] });

    response.end(readFileSync(path));
  } else {
    response.writeHead(404).end();
  }
});

await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));

const { port } = server.address() as { port: number };

let failures = 0;

for (const [name, type] of [
  ["chromium", chromium],
  ["firefox", firefox],
  ["webkit", webkit],
] as const) {
  const browser = await type.launch({ headless: true });

  try {
    for (const [backend, csp, expected] of PAGES) {
      const page = await browser.newPage();

      const query = new URLSearchParams({ backend, ...(csp === null ? {} : { csp }) });

      await page.goto(`http://127.0.0.1:${port}/page.html?${query}`);

      await page.waitForFunction(() => document.getElementById("out")?.textContent !== "not run", null, { timeout: 120000 });

      const text = (await page.textContent("#out")) ?? "";

      await page.close();

      const results = JSON.parse(text) as {
        families: Record<string, { backend?: string; error?: string; ok?: boolean; load?: number; first?: number }>;
        agree?: boolean;
      };

      const families = Object.values(results.families);

      const passed =
        families.length === 5 &&
        families.every((outcome) =>
          expected === "UNSUPPORTED" ? outcome.error === expected : outcome.backend === expected && outcome.ok === true,
        ) &&
        (expected !== "wasm" || results.agree === true);

      failures += passed ? 0 : 1;

      const times = Object.entries(results.families)
        .map(([family, outcome]) => `${family} ${outcome.load ?? "-"}+${outcome.first ?? "-"} ms`)
        .join(", ");

      console.log(`${passed ? "ok" : "FAILED"} ${name} ${browser.version()} backend ${backend} csp ${csp ?? "none"}: ${expected}; ${times}`);

      if (!passed) {
        console.log(text);
      }
    }
  } finally {
    await browser.close();
  }
}

server.close();

process.exitCode = failures > 0 ? 1 : 0;
