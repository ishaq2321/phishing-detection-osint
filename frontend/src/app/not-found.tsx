import { Shield } from "lucide-react";
import { LinkButton } from "@/components/ui/linkButton";
import { APP_NAME } from "@/lib/constants";

export default function NotFound() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-6 text-center">
      <Shield className="h-16 w-16 text-muted-foreground/40" />
      <div>
        <h1 className="text-6xl font-bold tracking-tighter">404</h1>
        <p className="mt-2 text-lg text-muted-foreground">
          This page doesn&apos;t exist in {APP_NAME}.
        </p>
      </div>
      <LinkButton href="/">
        Go to Dashboard
      </LinkButton>
    </div>
  );
}
