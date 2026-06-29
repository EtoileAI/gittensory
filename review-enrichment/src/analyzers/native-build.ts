// Native-build / install-cost dependency flag (#1512). Flags a newly added/changed dependency that triggers a
// native compile on install (npm: `node-gyp` with no prebuilt binary) or has no pure-Python wheel (PyPI:
// sdist-only) — hidden CI cold-start/install cost and a frequent cross-platform breakage source.
//
// Data sources: the npm registry packument (`versions[v].gypfile` + `versions[v].binary`) and the PyPI
// per-release JSON (`urls[].packagetype`). Both are free; keyed on package@version from the shipped extractor
// (`extractDependencyChanges`), so this analyzer never re-parses the diff.
//
// Distinct from #1474 (CVE scan) and the install-script auditor: those grade vulnerability/supply-chain risk;
// this grades INSTALL COST. A pure-JS package with a malicious postinstall is an install-script finding; a
// native module with no prebuilt that slows CI by 90s is a native-build finding.
//
// Fail-safe: returns [] on any network error or non-ok response (mirrors `queryOsv`). Forwards abort signals
// so the orchestrator's timeout can cancel in-flight registry fetches.
import type { EnrichRequest, NativeBuildFinding } from "../types.js";
import { extractDependencyChanges } from "./dependency-scan.js";

// Caps attacker-controlled input: a huge manifest diff cannot exhaust the shared registry budget. Matches the
// OSV/license/install-script analyzers' per-dependency query cap.
const MAX_DEPS_QUERIED = 25;

const NPM_PACKAGE_RE =
  /^(?:@[a-z0-9][a-z0-9._-]*\/[a-z0-9][a-z0-9._-]*|[a-z0-9][a-z0-9._-]*)$/;
const SEMVER_RE =
  /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
// PyPI normalized names: ASCII letters, digits, `.`, `_`, `-`; normalized to lowercase on the index.
const PYPI_PACKAGE_RE = /^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$/i;

interface NpmVersionManifest {
  /** npm sets `gypfile: true` when the version ships a `binding.gyp` (a node-gyp native build). */
  gypfile?: boolean;
  /** A `binary` field is the node-pre-gyp / prebuild-install convention for hosting prebuilt binaries. */
  binary?: unknown;
}
interface NpmPackument {
  versions?: Record<string, NpmVersionManifest>;
}
interface PypiRelease {
  /** Each url's `packagetype`: `sdist` (source), `bdist_wheel` (wheel), `bdist_egg`, … */
  urls?: Array<{ packagetype: string }>;
}

/** True when an npm version manifest declares a native build (gypfile) with NO prebuilt binary host. Pure.
 *  A `binary` field means prebuilt artifacts are fetched on install (no compile needed), so the cost is gone. */
export function hasNpmNativeBuild(manifest: NpmVersionManifest | undefined): boolean {
  if (!manifest) return false;
  if (manifest.gypfile !== true) return false;
  return manifest.binary == null;
}

/** True when a PyPI release ships ONLY an sdist (no `bdist_wheel`). Pure. An empty `urls` list is NOT flagged
 *  (no signal) — only a release that published a source distribution but no wheel carries the install cost. */
export function isPypiSdistOnly(release: PypiRelease | undefined): boolean {
  const urls = release?.urls ?? [];
  if (urls.length === 0) return false;
  return !urls.some((url) => url.packagetype === "bdist_wheel");
}

async function fetchJson<T>(
  fetchImpl: typeof fetch,
  url: string,
  signal?: AbortSignal,
): Promise<T | undefined> {
  const response = await fetchImpl(url, { signal });
  if (!response.ok) return undefined;
  return (await response.json()) as T;
}

type ScanOptions = { signal?: AbortSignal };

/** Analyzer entrypoint: changed npm/PyPI deps → registry → only the deps that carry native-build install cost. */
export async function scanNativeBuild(
  req: EnrichRequest,
  fetchImpl: typeof fetch = fetch,
  options: ScanOptions = {},
): Promise<NativeBuildFinding[]> {
  const changes = extractDependencyChanges(req.files ?? []).slice(0, MAX_DEPS_QUERIED);
  const findings: NativeBuildFinding[] = [];
  for (const change of changes) {
    if (options.signal?.aborted) break;
    if (change.ecosystem === "npm" && NPM_PACKAGE_RE.test(change.package) && SEMVER_RE.test(change.to)) {
      const data = await fetchJson<NpmPackument>(
        fetchImpl,
        `https://registry.npmjs.org/${encodeURIComponent(change.package)}`,
        options.signal,
      );
      if (hasNpmNativeBuild(data?.versions?.[change.to])) {
        findings.push({ package: change.package, version: change.to, ecosystem: "npm", reason: "node-gyp" });
      }
      continue;
    }
    if (change.ecosystem === "PyPI" && PYPI_PACKAGE_RE.test(change.package)) {
      const data = await fetchJson<PypiRelease>(
        fetchImpl,
        `https://pypi.org/pypi/${encodeURIComponent(change.package)}/${encodeURIComponent(change.to)}/json`,
        options.signal,
      );
      if (isPypiSdistOnly(data)) {
        findings.push({ package: change.package, version: change.to, ecosystem: "PyPI", reason: "no-wheel" });
      }
    }
  }
  return findings;
}
