"use client";

/**
 * useReducedMotion — returns `true` when the user prefers reduced
 * motion via their OS accessibility setting.
 *
 * Re-exported from Motion for convenience — allows components
 * outside of motion wrappers to conditionally skip animations.
 */

import { useReducedMotion as useMotionReducedMotion } from "motion/react";

export function useReducedMotion(): boolean {
  return useMotionReducedMotion() ?? false;
}
