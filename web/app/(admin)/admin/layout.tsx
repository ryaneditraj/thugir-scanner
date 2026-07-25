import { redirect } from "next/navigation";
import { getAdminContext } from "@/lib/auth/admin";
import { getPreviewTier } from "@/lib/admin/preview-tier";
import TierPreview from "@/components/admin/TierPreview";
import AdminNav from "@/components/admin/AdminNav";

export const dynamic = "force-dynamic";

// Second auth gate on top of normal user auth. If the signed-in user is not an active row in
// admin_users, we redirect away. The panel is robots-disallowed and no-store.
export default async function AdminLayout({ children }: { children: React.ReactNode }) {
  const admin = await getAdminContext();
  if (!admin) redirect("/login");
  const previewTier = await getPreviewTier(admin.userId);

  return (
    <div className="admin-shell">
      <div className="admin-bar">
        <span className="admin-id">
          ADMIN CONSOLE · <b>{admin.email}</b> · <span className="tag verified">{admin.role}</span>
        </span>
        <TierPreview initialOverride={previewTier} />
      </div>
      <AdminNav />
      {children}
    </div>
  );
}
