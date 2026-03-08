"use client";

/**
 * LinkButton — a Next.js Link rendered with button styling.
 *
 * Exists because the shadcn Button (v4 / base-ui) doesn't support
 * the Radix `asChild` pattern, and `buttonVariants` lives inside a
 * `"use client"` file so it can't be called from Server Components.
 */

import Link from "next/link";
import type { ComponentProps } from "react";
import type { VariantProps } from "class-variance-authority";
import { buttonVariants } from "@/components/ui/button";
import { cn } from "@/lib/utils";

type LinkButtonProps = ComponentProps<typeof Link> &
  VariantProps<typeof buttonVariants>;

export function LinkButton({
  className,
  variant,
  size,
  ...props
}: LinkButtonProps) {
  return (
    <Link
      className={cn(buttonVariants({ variant, size }), className)}
      {...props}
    />
  );
}
