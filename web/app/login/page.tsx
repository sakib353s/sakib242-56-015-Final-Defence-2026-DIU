"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { getToken, login } from "@/lib/auth";
import { ErrBanner, Field } from "@/components/ui";
import { ThemeToggle } from "@/components/theme";

export default function LoginPage() {
  const router = useRouter();
  const [roleHint, setRoleHint] = useState("1");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (getToken()) router.replace("/dashboard");
  }, [router]);

  const submit = useCallback(
    async (e: FormEvent) => {
      e.preventDefault();
      setErr(null);
      setBusy(true);
      try {
        await login({ username: username.trim().toLowerCase(), password });
        router.replace("/dashboard");
      } catch (ex) {
        setErr(ex);
        setBusy(false);
      }
    },
    [username, password, router],
  );

  return (
    <div className="login-page">
      <header className="login-head">
        <span className="login-word">CyberWatch-BD</span>
        <span className="login-sub">Sign in</span>
        <span className="login-attest">System checks passed · session recorded</span>
        <ThemeToggle />
        <button type="button" className="btn small" onClick={() => router.replace("/boot")}>
          Re-run system checks
        </button>
      </header>

      <main className="login-main">
        <div className="login-idblock" aria-hidden>
          <div className="login-idline big">CyberWatch-BD</div>
          <div className="login-idline name">MD Rafshan Rahman Sakib</div>
          <div className="login-idline id">242-56-015</div>
          <div className="login-idline aff">M.Sc in Cyber Security</div>
          <div className="login-idline aff">Department of Cyber Security</div>
          <div className="login-idline aff">Daffodil International University</div>
        </div>

        <form className="login-form" onSubmit={submit} aria-label="sign in">
          <div className="gate-title">Sign in to your account</div>
          <Field label="Role" hint="Your role is determined by your account">
            <select value={roleHint} onChange={(e) => setRoleHint(e.target.value)}>
              <option value="1">Administrator</option>
              <option value="2">Analyst</option>
              <option value="3">Observer</option>
            </select>
          </Field>
          <Field label="Username" hint="At least 3 characters">
            <input
              className="text"
              autoComplete="username"
              autoFocus
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              maxLength={64}
            />
          </Field>
          <Field label="Password" hint="Minimum 8 characters">
            <input
              className="text"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              maxLength={128}
            />
          </Field>
          {err ? <ErrBanner error={err} /> : null}
          <button
            type="submit"
            className="btn primary wide"
            disabled={busy || username.trim().length < 3 || password.length < 8}
          >
            {busy ? "Signing in…" : "Sign in"}
          </button>
          <div className="gate-hint">
            Every action is recorded in the audit log. Privileged and security-testing actions
            require an additional verification code.
          </div>
        </form>
      </main>
    </div>
  );
}
