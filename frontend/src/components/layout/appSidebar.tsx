"use client";

/**
 * AppSidebar — main application navigation sidebar.
 *
 * Desktop (≥ 1024px): Fixed left sidebar with icons + labels.
 * Tablet  (768–1023px): Collapsed icon-only rail, expands on hover.
 * Mobile  (< 768px): Hidden — navigation opens via Sheet in AppHeader.
 */

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  Search,
  History,
  BookOpen,
  Settings,
  type LucideIcon,
} from "lucide-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import { APP_NAME, APP_VERSION } from "@/lib/constants";
import { Logo } from "@/components/brand";

/* ------------------------------------------------------------------ */
/*  Navigation items (icons resolved statically)                      */
/* ------------------------------------------------------------------ */

interface SidebarNavItem {
  title: string;
  href: string;
  icon: LucideIcon;
}

const sidebarNavItems: SidebarNavItem[] = [
  { title: "Dashboard", href: "/", icon: LayoutDashboard },
  { title: "Analyse", href: "/analyze", icon: Search },
  { title: "History", href: "/history", icon: History },
  { title: "How It Works", href: "/how-it-works", icon: BookOpen },
  { title: "Settings", href: "/settings", icon: Settings },
];

/* ------------------------------------------------------------------ */
/*  NavLink (single item)                                             */
/* ------------------------------------------------------------------ */

interface NavLinkProps {
  href: string;
  title: string;
  Icon: LucideIcon;
  isActive: boolean;
  collapsed?: boolean;
}

function NavLink({ href, title, Icon, isActive, collapsed }: NavLinkProps) {
  const linkClasses = cn(
    "group flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-all min-h-[44px]",
    "hover:bg-accent hover:text-accent-foreground",
    "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
    isActive
      ? "bg-accent text-accent-foreground border-l-2 border-primary rounded-l-none"
      : "border-l-2 border-transparent text-muted-foreground hover:border-muted-foreground/30",
    collapsed && "justify-center px-2 border-l-0 rounded-l-lg",
  );

  if (collapsed) {
    return (
      <Tooltip>
        <TooltipTrigger
          render={
            <Link
              href={href}
              className={linkClasses}
              aria-current={isActive ? "page" : undefined}
            />
          }
        >
          <Icon className="h-4 w-4 shrink-0" aria-hidden="true" />
        </TooltipTrigger>
        <TooltipContent side="right">{title}</TooltipContent>
      </Tooltip>
    );
  }

  return (
    <Link
      href={href}
      className={linkClasses}
      aria-current={isActive ? "page" : undefined}
    >
      <Icon className="h-4 w-4 shrink-0" aria-hidden="true" />
      <span>{title}</span>
    </Link>
  );
}

/* ------------------------------------------------------------------ */
/*  Sidebar content (shared between desktop sidebar & mobile sheet)   */
/* ------------------------------------------------------------------ */

interface SidebarContentProps {
  collapsed?: boolean;
}

export function SidebarContent({ collapsed = false }: SidebarContentProps) {
  const pathname = usePathname();

  return (
    <div className="flex h-full flex-col">
      {/* Brand */}
<div
          className={cn(
            "flex h-14 items-center border-b px-4",
            collapsed && "justify-center px-2",
          )}
        >
          <Link
            href="/"
            className="flex items-center gap-2.5 rounded-sm font-semibold focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            aria-label={collapsed ? `${APP_NAME} — Go to dashboard` : undefined}
          >
            <div className="rounded-lg bg-primary/10 p-1.5">
              <Logo className="h-5 w-5 text-primary" />
            </div>
            {!collapsed && (
              <span className="text-base tracking-tight">{APP_NAME}</span>
            )}
          </Link>
        </div>

      {/* Navigation */}
      <ScrollArea className="flex-1 px-2 py-3">
        <nav aria-label="Main navigation" className="flex flex-col gap-1">
          {sidebarNavItems.map((item) => (
            <NavLink
              key={item.href}
              href={item.href}
              title={item.title}
              Icon={item.icon}
              isActive={
                item.href === "/"
                  ? pathname === "/"
                  : pathname.startsWith(item.href)
              }
              collapsed={collapsed}
            />
          ))}
        </nav>
      </ScrollArea>

      <Separator />

      {/* Footer */}
      <div
        className={cn(
          "p-4 text-xs text-muted-foreground",
          collapsed && "p-2 text-center",
        )}
      >
        {collapsed ? (
          <span className="text-[10px]">v{APP_VERSION}</span>
        ) : (
          <>
            <p className="font-medium">{APP_NAME}</p>
            <p>v{APP_VERSION} &middot; ELTE FI</p>
          </>
        )}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Desktop sidebar wrapper                                           */
/* ------------------------------------------------------------------ */

export function AppSidebar() {
  return (
    <>
      {/* Full sidebar — visible only on lg+ */}
      <aside
        className="hidden lg:flex lg:w-60 lg:flex-col lg:border-r bg-background"
        aria-label="Application sidebar"
      >
        <SidebarContent />
      </aside>

      {/* Collapsed rail — visible only on md (tablet) */}
      <aside
        className="hidden md:flex md:w-14 md:flex-col md:border-r lg:hidden bg-background"
        aria-label="Application sidebar (collapsed)"
      >
        <SidebarContent collapsed />
      </aside>
    </>
  );
}
