"use client";

import { useEffect, useState, type ReactNode } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ApiProblem } from "@/lib/api";
import { initTheme, watchSystem } from "@/lib/theme";
import { ToastProvider } from "./toast";
import { StepUpProvider } from "./stepup";

function ThemeSync() {
  useEffect(() => {
    initTheme();
    return watchSystem();
  }, []);
  return null;
}

export function Providers({ children }: { children: ReactNode }) {
  const [qc] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            retry: (count, err) => (err instanceof ApiProblem && err.status && err.status < 500 ? false : count < 1),
            staleTime: 5000,
            refetchOnWindowFocus: false,
          },
        },
      }),
  );
  return (
    <QueryClientProvider client={qc}>
      <ThemeSync />
      <ToastProvider>
        <StepUpProvider>{children}</StepUpProvider>
      </ToastProvider>
    </QueryClientProvider>
  );
}
