import { getServerSupabase, getServiceSupabase } from "../supabase/server";
import { IS_DEV_MODE, DEV_USER } from "../devmode";

export type AdminRole = "owner" | "analyst" | "support";

export interface AdminContext {
  userId: string;
  email: string | null;
  role: AdminRole;
}

// Resolve the current admin from the session. Returns null if not signed in or not an admin.
// This is a SECOND auth check layered on top of normal user auth (per the plan).
export async function getAdminContext(): Promise<AdminContext | null> {
  // DEV_MODE: act as a full owner so the admin console can be exercised without Supabase.
  if (IS_DEV_MODE) {
    return { userId: DEV_USER.id, email: DEV_USER.email, role: "owner" };
  }
  const supabase = getServerSupabase();
  const {
    data: { user }
  } = await supabase.auth.getUser();
  if (!user) return null;

  // Use the service client to read admin_users (RLS would also allow it for admins, but the
  // service read is unambiguous and avoids a recursive policy dependency at the gate).
  const svc = getServiceSupabase();
  const { data, error } = await svc
    .from("admin_users")
    .select("role, disabled")
    .eq("id", user.id)
    .single();
  if (error || !data || data.disabled) return null;
  return { userId: user.id, email: user.email ?? null, role: data.role as AdminRole };
}

const ROLE_RANK: Record<AdminRole, number> = { support: 0, analyst: 1, owner: 2 };
export function roleAtLeast(role: AdminRole, min: AdminRole): boolean {
  return ROLE_RANK[role] >= ROLE_RANK[min];
}

// Append-only audit write. Every admin mutation must call this.
export async function writeAudit(args: {
  actorAdminId: string;
  action: string;
  targetType?: string;
  targetId?: string;
  before?: unknown;
  after?: unknown;
  ip?: string;
}): Promise<void> {
  if (IS_DEV_MODE) return; // no audit sink without Supabase
  const svc = getServiceSupabase();
  await svc.from("admin_audit_log").insert({
    actor_admin_id: args.actorAdminId,
    action: args.action,
    target_type: args.targetType ?? null,
    target_id: args.targetId ?? null,
    before_json: args.before ?? null,
    after_json: args.after ?? null,
    ip: args.ip ?? null
  });
}
