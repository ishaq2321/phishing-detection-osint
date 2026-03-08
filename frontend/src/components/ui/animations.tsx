"use client";

/**
 * Reusable animation wrapper components powered by Motion (Framer Motion).
 *
 * Every wrapper automatically respects the user's `prefers-reduced-motion`
 * accessibility setting — when active, animations are replaced with
 * instant transitions (duration: 0).
 *
 * Components:
 *   FadeIn       — simple opacity fade
 *   SlideUp      — slide up with fade
 *   SlideIn      — slide in from left with fade
 *   ScaleIn      — scale from 0.95 with fade
 *   StaggerGroup — staggers its children's entrance
 *   StaggerItem  — individual item within a StaggerGroup
 */

import { type ReactNode } from "react";
import {
  motion,
  type Transition,
  type Variants,
  useReducedMotion,
} from "motion/react";

/* ------------------------------------------------------------------ */
/*  Shared defaults                                                   */
/* ------------------------------------------------------------------ */

const DEFAULT_DURATION = 0.35;
const DEFAULT_EASE = [0.25, 0.1, 0.25, 1] as const; // ease-out

function resolveTransition(
  reduced: boolean | null,
  duration = DEFAULT_DURATION,
): Transition {
  if (reduced) return { duration: 0 };
  return { duration, ease: DEFAULT_EASE };
}

/* ------------------------------------------------------------------ */
/*  Props shared by every wrapper                                     */
/* ------------------------------------------------------------------ */

interface AnimationWrapperProps {
  children: ReactNode;
  /** Extra class names forwarded to the wrapper div. */
  className?: string;
  /** Override the default animation duration (seconds). */
  duration?: number;
  /** Delay before the animation starts (seconds). */
  delay?: number;
}

/* ------------------------------------------------------------------ */
/*  FadeIn                                                            */
/* ------------------------------------------------------------------ */

export function FadeIn({
  children,
  className,
  duration,
  delay = 0,
}: AnimationWrapperProps) {
  const reduced = useReducedMotion();

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ ...resolveTransition(reduced, duration), delay }}
      className={className}
    >
      {children}
    </motion.div>
  );
}

/* ------------------------------------------------------------------ */
/*  SlideUp                                                           */
/* ------------------------------------------------------------------ */

export function SlideUp({
  children,
  className,
  duration,
  delay = 0,
}: AnimationWrapperProps) {
  const reduced = useReducedMotion();

  return (
    <motion.div
      initial={{ opacity: 0, y: reduced ? 0 : 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ ...resolveTransition(reduced, duration), delay }}
      className={className}
    >
      {children}
    </motion.div>
  );
}

/* ------------------------------------------------------------------ */
/*  SlideIn (from left)                                               */
/* ------------------------------------------------------------------ */

export function SlideIn({
  children,
  className,
  duration,
  delay = 0,
}: AnimationWrapperProps) {
  const reduced = useReducedMotion();

  return (
    <motion.div
      initial={{ opacity: 0, x: reduced ? 0 : -20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ ...resolveTransition(reduced, duration), delay }}
      className={className}
    >
      {children}
    </motion.div>
  );
}

/* ------------------------------------------------------------------ */
/*  ScaleIn                                                           */
/* ------------------------------------------------------------------ */

export function ScaleIn({
  children,
  className,
  duration,
  delay = 0,
}: AnimationWrapperProps) {
  const reduced = useReducedMotion();

  return (
    <motion.div
      initial={{ opacity: 0, scale: reduced ? 1 : 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ ...resolveTransition(reduced, duration), delay }}
      className={className}
    >
      {children}
    </motion.div>
  );
}

/* ------------------------------------------------------------------ */
/*  StaggerGroup + StaggerItem                                        */
/* ------------------------------------------------------------------ */

const staggerContainerVariants: Variants = {
  hidden: {},
  visible: {
    transition: {
      staggerChildren: 0.08,
    },
  },
};

const staggerItemVariants: Variants = {
  hidden: { opacity: 0, y: 12 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { duration: DEFAULT_DURATION, ease: DEFAULT_EASE },
  },
};

const staggerItemReduced: Variants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { duration: 0 } },
};

interface StaggerGroupProps {
  children: ReactNode;
  className?: string;
}

export function StaggerGroup({ children, className }: StaggerGroupProps) {
  return (
    <motion.div
      variants={staggerContainerVariants}
      initial="hidden"
      animate="visible"
      className={className}
    >
      {children}
    </motion.div>
  );
}

interface StaggerItemProps {
  children: ReactNode;
  className?: string;
}

export function StaggerItem({ children, className }: StaggerItemProps) {
  const reduced = useReducedMotion();

  return (
    <motion.div
      variants={reduced ? staggerItemReduced : staggerItemVariants}
      className={className}
    >
      {children}
    </motion.div>
  );
}
