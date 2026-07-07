import { loadMaskedSettings } from "@/lib/settings/store";
import { getAdminContext, roleAtLeast } from "@/lib/auth/admin";
import SettingsForm from "@/components/admin/SettingsForm";

export const dynamic = "force-dynamic";

export default async function AdminSettingsPage() {
  const admin = await getAdminContext();
  const canEdit = admin ? roleAtLeast(admin.role, "owner") : false;
  const settings = await loadMaskedSettings();

  return (
    <article>
      <h1 className="admin-h1">Platform settings</h1>
      <p className="dim" style={{ marginBottom: 20 }}>
        Every operational knob in one place — per-tier AI providers/models/keys, scan limits,
        abuse controls, and pricing. Changes are audited.
      </p>
      {!canEdit && (
        <p className="notice" style={{ marginBottom: 18 }}>
          You can view settings, but only an <b>owner</b> can change them.
        </p>
      )}
      <SettingsForm initial={settings} />
    </article>
  );
}
