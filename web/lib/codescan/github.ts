// Minimal public-GitHub reader for the code scanner. Uses two API calls (repo meta + recursive
// tree), then fetches raw blob contents (which don't count against the API rate limit). A
// GITHUB_TOKEN env var is used when present to raise the rate limit, but is not required.

export class RepoError extends Error {}

export interface RepoRef {
  owner: string;
  repo: string;
  branch?: string;
}

export interface RepoFile {
  path: string;
  ext: string;
  content: string;
}

const CODE_EXTS = new Set([
  "js", "jsx", "ts", "tsx", "mjs", "cjs", "py", "rb", "go", "php", "java", "kt", "cs", "rs",
  "yml", "yaml", "tf", "sh", "bash", "env", "ini", "cfg", "conf", "json", "vue", "svelte"
]);

const IGNORE_DIR = /(^|\/)(node_modules|dist|build|out|\.next|\.git|vendor|coverage|__pycache__|\.venv|venv|target|bin|obj|migrations\/.*generated)(\/|$)/i;
const IGNORE_FILE = /(\.min\.(js|css)|\.map|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Gemfile\.lock|\.lock)$/i;

export function parseRepoUrl(input: string): RepoRef {
  let s = input.trim();
  if (!s) throw new RepoError("Enter a GitHub repository URL.");
  s = s.replace(/^git@github\.com:/, "https://github.com/").replace(/\.git$/, "");
  if (!/^https?:\/\//i.test(s) && /^[\w.-]+\/[\w.-]+$/.test(s)) s = `https://github.com/${s}`;
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    throw new RepoError("That doesn't look like a valid URL.");
  }
  if (!/github\.com$/i.test(u.hostname)) throw new RepoError("Only public GitHub repositories are supported right now.");
  const parts = u.pathname.split("/").filter(Boolean);
  if (parts.length < 2) throw new RepoError("Use a full repo URL, e.g. https://github.com/owner/repo");
  const [owner, repo] = parts;
  let branch: string | undefined;
  if (parts[2] === "tree" && parts[3]) branch = parts[3];
  return { owner, repo, branch };
}

function ghHeaders(): Record<string, string> {
  const h: Record<string, string> = { Accept: "application/vnd.github+json", "User-Agent": "thugir-scanner" };
  if (process.env.GITHUB_TOKEN) h.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  return h;
}

async function defaultBranch(ref: RepoRef): Promise<string> {
  const res = await fetch(`https://api.github.com/repos/${ref.owner}/${ref.repo}`, { headers: ghHeaders() });
  if (res.status === 404) throw new RepoError("Repository not found (or it's private).");
  if (res.status === 403) throw new RepoError("GitHub rate limit hit. Try again shortly, or set a GITHUB_TOKEN.");
  if (!res.ok) throw new RepoError(`GitHub error (${res.status}).`);
  const data = await res.json();
  return data.default_branch || "main";
}

interface TreeEntry { path: string; type: string; size?: number }

export interface FetchedRepo {
  ref: Required<RepoRef>;
  files: RepoFile[];
  totalBlobs: number;
  scanned: number;
  truncated: boolean;
}

// Fetch a capped set of code files from the repo for scanning.
export async function fetchRepoFiles(
  input: string,
  opts: { maxFiles?: number; maxBytesPerFile?: number } = {}
): Promise<FetchedRepo> {
  const maxFiles = opts.maxFiles ?? 120;
  const maxBytes = opts.maxBytesPerFile ?? 400_000;
  const ref = parseRepoUrl(input);
  const branch = ref.branch || (await defaultBranch(ref));

  const treeRes = await fetch(
    `https://api.github.com/repos/${ref.owner}/${ref.repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`,
    { headers: ghHeaders() }
  );
  if (treeRes.status === 404) throw new RepoError("Branch or repository not found.");
  if (treeRes.status === 403) throw new RepoError("GitHub rate limit hit. Try again shortly, or set a GITHUB_TOKEN.");
  if (!treeRes.ok) throw new RepoError(`GitHub error reading the file tree (${treeRes.status}).`);
  const treeJson = await treeRes.json();
  const tree: TreeEntry[] = treeJson.tree ?? [];

  const candidates = tree.filter((e) => {
    if (e.type !== "blob") return false;
    if (IGNORE_DIR.test(e.path) || IGNORE_FILE.test(e.path)) return false;
    if ((e.size ?? 0) > maxBytes) return false;
    const ext = e.path.split(".").pop()?.toLowerCase() ?? "";
    // ".env" style dotfiles have no extension after split — handle by basename.
    const base = e.path.split("/").pop() ?? "";
    if (/^\.env(\..+)?$/i.test(base)) return true;
    return CODE_EXTS.has(ext);
  });

  const totalBlobs = candidates.length;
  const picked = candidates.slice(0, maxFiles);

  const files: RepoFile[] = [];
  // Fetch raw contents with a small concurrency pool.
  const queue = [...picked];
  async function worker() {
    while (queue.length) {
      const entry = queue.shift()!;
      const rawUrl = `https://raw.githubusercontent.com/${ref.owner}/${ref.repo}/${branch}/${entry.path
        .split("/")
        .map(encodeURIComponent)
        .join("/")}`;
      try {
        const r = await fetch(rawUrl, { headers: { "User-Agent": "thugir-scanner" } });
        if (!r.ok) continue;
        const content = (await r.text()).slice(0, maxBytes);
        files.push({ path: entry.path, ext: entry.path.split(".").pop()?.toLowerCase() ?? "", content });
      } catch {
        /* skip unreadable file */
      }
    }
  }
  await Promise.all([worker(), worker(), worker(), worker(), worker(), worker()]);

  return {
    ref: { owner: ref.owner, repo: ref.repo, branch },
    files,
    totalBlobs,
    scanned: files.length,
    truncated: totalBlobs > picked.length
  };
}
