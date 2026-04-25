/**
 * Application-wide constants.
 *
 * Centralises every magic string, number, and mapping so that the rest
 * of the codebase stays clean and DRY.
 */

/** Default backend API base URL (overridden by `NEXT_PUBLIC_API_URL`). */
export const DEFAULT_API_URL = "http://localhost:8000";

/** Resolved API base URL. */
export const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_URL ?? DEFAULT_API_URL;

/* ------------------------------------------------------------------ */
/*  Threat-level presentation                                         */
/* ------------------------------------------------------------------ */

import {
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Skull,
  type LucideIcon,
} from "lucide-react";
import type { ThreatLevel } from "@/types";

interface ThreatLevelMeta {
  label: string;
  icon: LucideIcon;
  colorClass: string;
  bgClass: string;
  borderClass: string;
}

export const THREAT_LEVEL_MAP: Record<ThreatLevel, ThreatLevelMeta> = {
  safe: {
    label: "Safe",
    icon: ShieldCheck,
    colorClass: "text-green-600 dark:text-green-400",
    bgClass: "bg-green-50 dark:bg-green-950",
    borderClass: "border-green-200 dark:border-green-800",
  },
  suspicious: {
    label: "Suspicious",
    icon: ShieldAlert,
    colorClass: "text-amber-600 dark:text-amber-400",
    bgClass: "bg-amber-50 dark:bg-amber-950",
    borderClass: "border-amber-200 dark:border-amber-800",
  },
  dangerous: {
    label: "Dangerous",
    icon: ShieldX,
    colorClass: "text-red-600 dark:text-red-400",
    bgClass: "bg-red-50 dark:bg-red-950",
    borderClass: "border-red-200 dark:border-red-800",
  },
  critical: {
    label: "Critical",
    icon: Skull,
    colorClass: "text-violet-600 dark:text-violet-400",
    bgClass: "bg-violet-50 dark:bg-violet-950",
    borderClass: "border-violet-200 dark:border-violet-800",
  },
};

/* ------------------------------------------------------------------ */
/*  Scoring weights (mirrors backend/api/orchestrator.py)             */
/* ------------------------------------------------------------------ */

/** For URL analysis: ML model is primary, NLP supplements. */
export const URL_SCORING_WEIGHTS = {
  ml: 0.85,
  text: 0.15,
} as const;

/** For email/text analysis: NLP is primary, URL + OSINT supplement. */
export const TEXT_SCORING_WEIGHTS = {
  text: 0.55,
  url: 0.25,
  osint: 0.20,
} as const;

/** Model performance on the held-out test set (5,009 samples). */
export const MODEL_METRICS = {
  accuracy: 0.9645,
  f1: 0.9639,
  auc: 0.9941,
  prAuc: 0.9948,
  featureCount: 21,
  trainSamples: 23_374,
  testSamples: 5_009,
} as const;

/* ------------------------------------------------------------------ */
/*  Navigation                                                        */
/* ------------------------------------------------------------------ */

export interface NavItem {
  title: string;
  href: string;
  /** Lucide icon name (used to dynamically look up icons). */
  icon: string;
}

export const NAV_ITEMS: NavItem[] = [
  { title: "Dashboard", href: "/", icon: "LayoutDashboard" },
  { title: "Analyze", href: "/analyze", icon: "Search" },
  { title: "History", href: "/history", icon: "History" },
  { title: "How It Works", href: "/how-it-works", icon: "BookOpen" },
  { title: "Settings", href: "/settings", icon: "Settings" },
] as const;

/* ------------------------------------------------------------------ */
/*  App metadata                                                      */
/* ------------------------------------------------------------------ */

export const APP_NAME = "PhishGuard";
export const APP_TAGLINE = "OSINT-Enhanced Phishing Detection";
export const APP_VERSION = "1.0.0";
