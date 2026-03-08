"use client";

/**
 * PageTransition — wraps page content with a fade+slide-up entrance
 * animation.  Respects `prefers-reduced-motion`.
 *
 * Usage:
 *   <PageTransition>
 *     <h1>My Page</h1>
 *     ...
 *   </PageTransition>
 */

import { type ReactNode } from "react";
import { motion, useReducedMotion } from "motion/react";

interface PageTransitionProps {
  children: ReactNode;
  className?: string;
}

export function PageTransition({ children, className }: PageTransitionProps) {
  const reduced = useReducedMotion();

  return (
    <motion.div
      initial={{ opacity: 0, y: reduced ? 0 : 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={
        reduced
          ? { duration: 0 }
          : { duration: 0.3, ease: [0.25, 0.1, 0.25, 1] }
      }
      className={className}
    >
      {children}
    </motion.div>
  );
}
