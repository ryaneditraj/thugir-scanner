import { Suspense } from "react";
import LoginForm from "@/components/LoginForm";

export default function LoginPage() {
  return (
    <div className="login-wrap">
      <Suspense fallback={<article className="login-card"><p className="muted">Loading…</p></article>}>
        <LoginForm />
      </Suspense>
    </div>
  );
}
