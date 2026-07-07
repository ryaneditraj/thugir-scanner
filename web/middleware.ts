import { NextResponse, type NextRequest } from "next/server";
import { createServerClient, type CookieOptions } from "@supabase/ssr";

// Guards authenticated surfaces. Unauthenticated requests to /dashboard, /scans, /admin
// are redirected to /login. The deeper admin role + 2FA check happens in the admin layout
// (getAdminContext) because middleware should stay lightweight.
const PROTECTED = [/^\/dashboard/, /^\/scans\//, /^\/admin/];

export async function middleware(req: NextRequest) {
  // DEV_MODE: auth is bypassed everywhere so protected surfaces are reachable without Supabase.
  if (process.env.DEV_MODE === "1") return NextResponse.next();

  const path = req.nextUrl.pathname;
  if (!PROTECTED.some((re) => re.test(path))) return NextResponse.next();

  let res = NextResponse.next({ request: { headers: req.headers } });
  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        get: (name: string) => req.cookies.get(name)?.value,
        set: (name: string, value: string, options: CookieOptions) => {
          res.cookies.set({ name, value, ...options });
        },
        remove: (name: string, options: CookieOptions) => {
          res.cookies.set({ name, value: "", ...options });
        }
      }
    }
  );
  const {
    data: { user }
  } = await supabase.auth.getUser();
  if (!user) {
    const url = req.nextUrl.clone();
    url.pathname = "/login";
    url.searchParams.set("next", path);
    return NextResponse.redirect(url);
  }
  return res;
}

export const config = {
  matcher: ["/dashboard/:path*", "/scans/:path*", "/admin/:path*"]
};
