/**
 * App shell layout — wraps all application pages with the sidebar,
 * header, and footer.  Uses a Next.js route group `(app)` so the
 * URL structure is unaffected.
 */

import { AppSidebar } from "@/components/layout/appSidebar";
import { AppHeader } from "@/components/layout/appHeader";
import { AppFooter } from "@/components/layout/appFooter";

export default function AppShellLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <div className="flex h-screen overflow-hidden">
      {/* Sidebar (desktop + tablet) */}
      <AppSidebar />

      {/* Main column: header + scrollable content + footer */}
      <div className="flex flex-1 flex-col overflow-hidden">
        <AppHeader />

        <main
          id="main-content"
          className="flex-1 overflow-y-auto"
        >
          <div className="mx-auto max-w-6xl px-4 py-6 sm:px-6 lg:px-8">
            {children}
          </div>
        </main>

        <AppFooter />
      </div>
    </div>
  );
}
