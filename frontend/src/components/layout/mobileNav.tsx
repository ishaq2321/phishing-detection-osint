"use client";

/**
 * MobileNav — fixed bottom navigation bar for mobile devices.
 *
 * Visible only below the `md` breakpoint (< 768px). Provides quick
 * access to the four primary routes with touch-friendly 44×48px
 * targets meeting WCAG 2.1 AA guidelines.
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
import { cn } from "@/lib/utils";

interface NavItem {
  title: string;
  href: string;
  icon: LucideIcon;
}

const navItems: NavItem[] = [
  { title: "Analyse", href: "/analyze", icon: Search },
  { title: "Dashboard", href: "/dashboard", icon: LayoutDashboard },
  { title: "History", href: "/history", icon: History },
  { title: "Learn", href: "/how-it-works", icon: BookOpen },
  { title: "Settings", href: "/settings", icon: Settings },
];

export function MobileNav() {
  const pathname = usePathname();

  return (
    <nav
      aria-label="Mobile navigation"
      className="fixed inset-x-0 bottom-0 z-50 border-t bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/80 md:hidden"
    >
      <div className="flex items-center justify-around">
        {navItems.map(({ title, href, icon: Icon }) => {
          const isActive =
            href === "/" ? pathname === "/" : pathname.startsWith(href);

          return (
            <Link
              key={href}
              href={href}
              className={cn(
                "flex min-h-[48px] min-w-[44px] flex-1 flex-col items-center justify-center gap-0.5 py-2 text-[10px] font-medium transition-colors",
                "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-inset",
                isActive
                  ? "text-primary"
                  : "text-muted-foreground hover:text-foreground",
              )}
              aria-current={isActive ? "page" : undefined}
            >
              <Icon className={cn("h-5 w-5", isActive && "text-primary")} aria-hidden="true" />
              <span>{title}</span>
            </Link>
          );
        })}
      </div>
    </nav>
  );
}
