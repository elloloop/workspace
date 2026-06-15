// Helpers that run at build time to enrich pages with metadata.

import { execSync } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const REPO_ROOT = path.resolve(
  fileURLToPath(new URL("../../../", import.meta.url)),
);

/**
 * Returns the most recent commit date (YYYY-MM-DD) for the .astro file backing
 * the given page URL. Falls back to today's date if git is unavailable or the
 * file is untracked.
 */
export function getLastUpdated(pageUrlPath: string): string {
  const today = new Date().toISOString().slice(0, 10);
  const astroPath = pageUrlToAstroPath(pageUrlPath);
  if (!astroPath || !existsSync(astroPath)) return today;
  try {
    const out = execSync(
      `git log -1 --format=%cd --date=short -- "${astroPath}"`,
      { cwd: REPO_ROOT, stdio: ["ignore", "pipe", "ignore"] },
    )
      .toString()
      .trim();
    return out || today;
  } catch {
    return today;
  }
}

/**
 * Returns the GitHub-edit URL for the .astro file backing the given page URL.
 */
export function getEditUrl(pageUrlPath: string): string {
  const astroPath = pageUrlToAstroPath(pageUrlPath);
  if (!astroPath) {
    return "https://github.com/elloloop/workspace/tree/main/docs-site";
  }
  const rel = path.relative(REPO_ROOT, astroPath);
  return `https://github.com/elloloop/workspace/edit/main/${rel}`;
}

function pageUrlToAstroPath(pageUrlPath: string): string | null {
  // pageUrlPath looks like "/workspace/docs/quickstart/" or
  // "/workspace/" for the root. Strip the base and the trailing slash.
  const base = "/workspace";
  let p = pageUrlPath.startsWith(base) ? pageUrlPath.slice(base.length) : pageUrlPath;
  p = p.replace(/^\//, "").replace(/\/$/, "");
  const root = path.join(REPO_ROOT, "docs-site", "src", "pages");
  if (!p) return path.join(root, "index.astro");
  // Try `<path>.astro` first, fall back to `<path>/index.astro`.
  const direct = path.join(root, `${p}.astro`);
  if (existsSync(direct)) return direct;
  const indexed = path.join(root, p, "index.astro");
  if (existsSync(indexed)) return indexed;
  return null;
}

let starsCache: string | null | undefined;

/**
 * Fetches the GitHub star count for the repo, formatted as "1.2k" or "342".
 * Returns null on any failure (no network, rate limited, 404). Cached for the
 * lifetime of the build.
 */
export async function getGithubStars(): Promise<string | null> {
  if (starsCache !== undefined) return starsCache;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);
    const res = await fetch(
      "https://api.github.com/repos/elloloop/workspace",
      {
        headers: { Accept: "application/vnd.github+json" },
        signal: controller.signal,
      },
    );
    clearTimeout(timeout);
    if (!res.ok) {
      starsCache = null;
      return starsCache;
    }
    const json = (await res.json()) as { stargazers_count?: number };
    const n = json.stargazers_count;
    if (typeof n !== "number") {
      starsCache = null;
      return starsCache;
    }
    starsCache = formatStars(n);
    return starsCache;
  } catch {
    starsCache = null;
    return starsCache;
  }
}

function formatStars(n: number): string {
  if (n >= 1000) {
    const k = (n / 1000).toFixed(1).replace(/\.0$/, "");
    return `${k}k`;
  }
  return String(n);
}
