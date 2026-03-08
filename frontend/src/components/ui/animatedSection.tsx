"use client";

/**
 * AnimatedSection — wraps a section of the how-it-works page with
 * a viewport-triggered fade-in animation.  Uses `whileInView` so
 * sections animate as the user scrolls.
 */

import { type ReactNode } from "react";
import { motion, useReducedMotion } from "motion/react";

interface AnimatedSectionProps {
  children: ReactNode;
  className?: string;
  delay?: number;
}

export function AnimatedSection({
  children,
  className,
  delay = 0,
}: AnimatedSectionProps) {
  const reduced = useReducedMotion();

  return (
    <motion.section
      initial={{ opacity: 0, y: reduced ? 0 : 16 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-40px" }}
      transition={
        reduced
          ? { duration: 0 }
          : { duration: 0.4, ease: [0.25, 0.1, 0.25, 1], delay }
      }
      className={className}
    >
      {children}
    </motion.section>
  );
}
