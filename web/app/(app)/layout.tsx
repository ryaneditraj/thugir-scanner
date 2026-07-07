// Authed app pages (dashboard, scan detail) render directly in <main>, so they need to clear
// the fixed transparent header. The marketing hero handles its own offset; these don't.
export default function AppLayout({ children }: { children: React.ReactNode }) {
  return <div className="app-shell">{children}</div>;
}
