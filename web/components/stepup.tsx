"use client";

import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from "react";
import { get } from "@/lib/api";
import { Modal, Field } from "./ui";

interface StepUpApi {
  requestTotp: (reason: string) => Promise<string | null>;
}

const Ctx = createContext<StepUpApi>({ requestTotp: async () => null });

export function useStepUp(): StepUpApi {
  return useContext(Ctx);
}

export function StepUpProvider({ children }: { children: ReactNode }) {
  const [prompt, setPrompt] = useState<{ reason: string; resolve: (code: string | null) => void } | null>(null);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const codeRef = useRef<HTMLInputElement>(null);
  const enforcedRef = useRef<boolean | null>(null);

  const stepupEnforced = useCallback(async () => {
    if (enforcedRef.current === null) {
      try {
        const cfg = await get<{ totp_stepup_required?: boolean }>("/config");
        enforcedRef.current = cfg.totp_stepup_required === true;
      } catch {
        enforcedRef.current = true; // fail-closed: if we can't read policy, demand a code
      }
    }
    return enforcedRef.current;
  }, []);

  const requestTotp = useCallback(
    async (reason: string): Promise<string | null> => {
      if (!(await stepupEnforced())) return "LAB-SKIP";
      return new Promise<string | null>((resolve) => {
        setCode("");
        setBusy(false);
        setPrompt({ reason, resolve });
      });
    },
    [stepupEnforced],
  );

  const close = useCallback(
    (val: string | null) => {
      prompt?.resolve(val);
      setPrompt(null);
    },
    [prompt],
  );

  const submit = useCallback(() => {
    if (!/^\d{6}$/.test(code)) return;
    // Step-up codes are single-use per operation; the value never persists to storage.
    setBusy(true);
    close(code);
  }, [code, close]);

  const api = useMemo(() => ({ requestTotp }), [requestTotp]);

  return (
    <Ctx.Provider value={api}>
      {children}
      {prompt ? (
        <Modal
          title="Verification required"
          onClose={() => close(null)}
          footer={
            <>
              <button type="button" className="btn" onClick={() => close(null)}>
                Cancel
              </button>
              <button type="button" className="btn primary" disabled={busy || !/^\d{6}$/.test(code)} onClick={submit}>
                Authorize
              </button>
            </>
          }
        >
          <div className="page-note" style={{ marginBottom: 12, color: "var(--warn)" }}>
            This action requires verification: {prompt.reason}
          </div>
          <Field label="Enter your 6-digit code" hint="Valid for about 30 seconds and for this action only">
            <input
              ref={codeRef}
              className="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={6}
              placeholder="123456"
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
              onKeyDown={(e) => e.key === "Enter" && submit()}
            />
          </Field>
        </Modal>
      ) : null}
    </Ctx.Provider>
  );
}
