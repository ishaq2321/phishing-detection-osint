"use client";

/**
 * AppHeader — top bar with mobile menu trigger, page title, theme
 * toggle, and backend health status indicator.
 */

import { useState } from "react";
import { Menu, Shield, Circle } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { ThemeToggle } from "@/components/layout/themeToggle";
import { SidebarContent } from "@/components/layout/appSidebar";
import { useHealth } from "@/hooks";
import { cn } from "@/lib/utils";
import { APP_NAME } from "@/lib/constants";

export function AppHeader() {
  const [mobileOpen, setMobileOpen] = useState(false);
  const { data: health } = useHealth(30_000);

  const statusColor =
    health?.status === "healthy"
      ? "text-green-500"
      : health?.status === "degraded"
        ? "text-amber-500"
        : health
          ? "text-red-500"
          : "text-muted-foreground";

  const statusLabel =
    health?.status === "healthy"
      ? "Backend connected"
      : health?.status === "degraded"
        ? "Backend degraded"
        : health
          ? "Backend unhealthy"
          : "Checking backend…";

  return (
    <header className="sticky top-0 z-40 flex h-14 items-center gap-3 border-b bg-background/80 px-4 backdrop-blur-sm">
      {/* Mobile menu button — visible below md */}
      <Button
        variant="ghost"
        size="icon"
        className="md:hidden"
        onClick={() => setMobileOpen(true)}
        aria-label="Open navigation menu"
      >
        <Menu className="h-5 w-5" />
      </Button>

      {/* Mobile sheet */}
      <Sheet open={mobileOpen} onOpenChange={setMobileOpen}>
        <SheetContent
          side="left"
          className="w-64 p-0"
          showCloseButton
        >
          <SheetHeader className="sr-only">
            <SheetTitle>{APP_NAME} navigation</SheetTitle>
          </SheetHeader>
          <div onClick={() => setMobileOpen(false)}>
            <SidebarContent />
          </div>
        </SheetContent>
      </Sheet>

      {/* Mobile logo — visible below md */}
      <div className="flex items-center gap-2 md:hidden">
        <Shield className="h-5 w-5 text-primary" />
        <span className="font-semibold">{APP_NAME}</span>
      </div>

      {/* Spacer */}
      <div className="flex-1" />

      {/* Health indicator */}
      <div
        className="flex items-center gap-1.5 text-xs text-muted-foreground"
        aria-label={statusLabel}
        title={statusLabel}
      >
        <Circle
          className={cn("h-2 w-2 fill-current", statusColor)}
        />
        <span className="hidden sm:inline">{statusLabel}</span>
      </div>

      {/* Theme toggle */}
      <ThemeToggle />
    </header>
  );
}
