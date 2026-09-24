import { Chrome, WsProvider } from "@/components/chrome";
import { AuthGuard } from "@/components/ui";

export default function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <AuthGuard>
      <WsProvider>
        <Chrome>{children}</Chrome>
      </WsProvider>
    </AuthGuard>
  );
}
