/**
 * AppFooter — minimal footer with ELTE branding for the app shell.
 */

import { APP_NAME } from "@/lib/constants";

export function AppFooter() {
  return (
    <footer className="border-t px-4 py-4 text-center text-xs text-muted-foreground">
      <p>
        {APP_NAME} &copy; {new Date().getFullYear()} &middot; Ishaq Muhammad
        (PXPRGK) &middot; ELTE Faculty of Informatics
      </p>
    </footer>
  );
}
