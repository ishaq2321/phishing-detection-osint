"use client";

/**
 * ShareActions — copy-to-clipboard, share link, and print buttons
 * for analysis results.
 */

import { useState, useCallback } from "react";
import { Copy, Check, Printer, FileJson, Link2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import type { AnalysisResponse } from "@/types";
import { showSuccess, showError } from "@/lib/toast";

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

/** Clipboard write with fallback for older browsers. */
async function writeToClipboard(text: string): Promise<void> {
  if (navigator.clipboard) {
    await navigator.clipboard.writeText(text);
    return;
  }
  /* Fallback: hidden textarea + execCommand */
  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  document.body.appendChild(textarea);
  textarea.select();
  document.execCommand("copy");
  document.body.removeChild(textarea);
}

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

function buildTextSummary(result: AnalysisResponse, content: string): string {
  const v = result.verdict;
  const lines = [
    `PhishGuard Analysis Report`,
    `══════════════════════════`,
    ``,
    `Content: ${content.length > 120 ? content.slice(0, 120) + "…" : content}`,
    `Verdict: ${v.isPhishing ? "PHISHING DETECTED" : "SAFE"}`,
    `Threat Level: ${v.threatLevel.toUpperCase()}`,
    `Confidence: ${Math.round(v.confidenceScore * 100)}%`,
    `Recommendation: ${v.recommendation}`,
    ``,
  ];

  if (v.reasons.length > 0) {
    lines.push(`Risk Indicators:`);
    v.reasons.forEach((r) => lines.push(`  • ${r}`));
    lines.push(``);
  }

  lines.push(`Analysis Time: ${result.analysisTime.toFixed(2)}s`);
  lines.push(`Date: ${new Date(result.analyzedAt).toLocaleString()}`);
  return lines.join("\n");
}

/* ------------------------------------------------------------------ */
/*  Component                                                         */
/* ------------------------------------------------------------------ */

interface ShareActionsProps {
  result: AnalysisResponse;
  /** The content string that was originally analysed. */
  content: string;
}

export function ShareActions({ result, content }: ShareActionsProps) {
  const [copiedText, setCopiedText] = useState(false);
  const [copiedJson, setCopiedJson] = useState(false);
  const [copiedLink, setCopiedLink] = useState(false);

  const copyText = useCallback(async () => {
    try {
      await writeToClipboard(buildTextSummary(result, content));
      setCopiedText(true);
      showSuccess("Summary copied to clipboard");
      setTimeout(() => setCopiedText(false), 2000);
    } catch {
      showError("Failed to copy", "Your browser may not support clipboard access.");
    }
  }, [result, content]);

  const copyJson = useCallback(async () => {
    try {
      await writeToClipboard(JSON.stringify(result, null, 2));
      setCopiedJson(true);
      showSuccess("JSON copied to clipboard");
      setTimeout(() => setCopiedJson(false), 2000);
    } catch {
      showError("Failed to copy", "Your browser may not support clipboard access.");
    }
  }, [result]);

  const copyLink = useCallback(async () => {
    try {
      await writeToClipboard(window.location.href);
      setCopiedLink(true);
      showSuccess("Link copied to clipboard");
      setTimeout(() => setCopiedLink(false), 2000);
    } catch {
      showError("Failed to copy link");
    }
  }, []);

  const handlePrint = useCallback(() => {
    window.print();
  }, []);

  return (
    <div className="flex flex-wrap gap-2">
      {/* Copy text summary */}
      <Tooltip>
        <TooltipTrigger
          render={
            <Button
              variant="outline"
              size="sm"
              onClick={copyText}
            />
          }
        >
          {copiedText ? (
            <Check className="mr-1.5 h-3.5 w-3.5 text-green-500 dark:text-green-400" />
          ) : (
            <Copy className="mr-1.5 h-3.5 w-3.5" />
          )}
          {copiedText ? "Copied!" : "Copy Summary"}
        </TooltipTrigger>
        <TooltipContent>Copy formatted text summary</TooltipContent>
      </Tooltip>

      {/* Copy JSON */}
      <Tooltip>
        <TooltipTrigger
          render={
            <Button
              variant="outline"
              size="sm"
              onClick={copyJson}
            />
          }
        >
          {copiedJson ? (
            <Check className="mr-1.5 h-3.5 w-3.5 text-green-500 dark:text-green-400" />
          ) : (
            <FileJson className="mr-1.5 h-3.5 w-3.5" />
          )}
          {copiedJson ? "Copied!" : "Copy JSON"}
        </TooltipTrigger>
        <TooltipContent>Copy raw API response as JSON</TooltipContent>
      </Tooltip>

      {/* Copy link */}
      <Tooltip>
        <TooltipTrigger
          render={
            <Button
              variant="outline"
              size="sm"
              onClick={copyLink}
            />
          }
        >
          {copiedLink ? (
            <Check className="mr-1.5 h-3.5 w-3.5 text-green-500 dark:text-green-400" />
          ) : (
            <Link2 className="mr-1.5 h-3.5 w-3.5" />
          )}
          {copiedLink ? "Copied!" : "Copy Link"}
        </TooltipTrigger>
        <TooltipContent>Copy shareable link to this page</TooltipContent>
      </Tooltip>

      {/* Print */}
      <Tooltip>
        <TooltipTrigger
          render={
            <Button
              variant="outline"
              size="sm"
              onClick={handlePrint}
            />
          }
        >
          <Printer className="mr-1.5 h-3.5 w-3.5" />
          Print
        </TooltipTrigger>
        <TooltipContent>Print this report</TooltipContent>
      </Tooltip>
    </div>
  );
}
