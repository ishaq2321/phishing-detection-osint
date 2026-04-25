"use client";

/**
 * History page — displays all past analyses in a sortable, filterable
 * data table with search, export, and per-row actions.
 *
 * Storage is client-side only (localStorage), making it suitable for
 * the thesis prototype without needing a backend database.
 */

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import {
  Download,
  FileJson,
  FileSpreadsheet,
  History,
  Search,
  Trash2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import dynamic from "next/dynamic";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useResult } from "@/lib/resultsContext";

/* Dynamically import heavy table component to reduce initial bundle */
const HistoryTable = dynamic(
  () => import("@/components/history/historyTable").then((m) => m.HistoryTable),
  { ssr: false },
);
import { PageTransition } from "@/components/ui/pageTransition";
import { FadeIn } from "@/components/ui/animations";
import {
  type HistoryEntry,
  getHistory,
  deleteEntry,
  clearHistory,
  exportToCsv,
  exportToJson,
} from "@/lib/storage/historyStore";
import { LinkButton } from "@/components/ui/linkButton";
import { showSuccess, showInfo } from "@/lib/toast";

export default function HistoryPage() {
  const router = useRouter();
  const { setResult } = useResult();

  /* ── Local state (hydrated on mount) ───────────────────────────── */
  const [entries, setEntries] = useState<HistoryEntry[]>([]);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    const frame = requestAnimationFrame(() => {
      setMounted(true);
      setEntries(getHistory());
    });
    return () => cancelAnimationFrame(frame);
  }, []);

  /* ── Actions ───────────────────────────────────────────────────── */

  /** Navigate to the results page with the stored response. */
  const handleView = useCallback(
    (entry: HistoryEntry) => {
      setResult({
        response: entry.response,
        content: entry.content,
        contentType: entry.contentType,
        historyId: entry.id,
      });
      router.push("/results");
    },
    [router, setResult],
  );

  /** Navigate to the analyse page with the content pre-filled. */
  const handleReanalyse = useCallback(
    (entry: HistoryEntry) => {
      const params = new URLSearchParams({
        content: entry.content,
        type: entry.contentType,
      });
      router.push(`/analyze?${params.toString()}`);
    },
    [router],
  );

  /** Delete a single entry and refresh state. */
  const handleDelete = useCallback((entry: HistoryEntry) => {
    deleteEntry(entry.id);
    setEntries(getHistory());
    showSuccess("Entry deleted");
  }, []);

  /** Clear all history entries. */
  const handleClearAll = useCallback(() => {
    clearHistory();
    setEntries([]);
    showSuccess("History cleared", "All analysis records have been deleted.");
  }, []);

  /* ── Prevent hydration mismatch ────────────────────────────────── */
  if (!mounted) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight sm:text-3xl">
            Analysis History
          </h1>
          <p className="text-muted-foreground">
            Review and manage your past analysis results.
          </p>
        </div>
        <div className="h-64 rounded-lg border bg-muted/30 animate-pulse" />
      </div>
    );
  }

  /* ── Empty state ───────────────────────────────────────────────── */
  if (entries.length === 0) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight sm:text-3xl">
            Analysis History
          </h1>
          <p className="text-muted-foreground">
            Review and manage your past analysis results.
          </p>
        </div>

        <Card>
          <CardHeader className="items-center text-center">
            <div className="rounded-full border bg-muted p-4">
              <History className="h-8 w-8 text-muted-foreground" aria-hidden="true" />
            </div>
            <CardTitle>No Analyses Yet</CardTitle>
            <CardDescription>
              Your analysis history will appear here once you start analysing
              URLs, emails, or text.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex justify-center">
            <LinkButton href="/analyze">
              <Search className="mr-2 h-4 w-4" aria-hidden="true" />
              Start Analysing
            </LinkButton>
          </CardContent>
        </Card>
      </div>
    );
  }

  /* ── Main view ─────────────────────────────────────────────────── */
  return (
    <PageTransition>
      <div className="space-y-6">
        {/* Header */}
        <FadeIn>
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight sm:text-3xl">
            Analysis History
          </h1>
          <p className="text-muted-foreground">
            {entries.length} analysis result{entries.length !== 1 ? "s" : ""}{" "}
            stored locally.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {/* Export dropdown */}
          <DropdownMenu>
            <DropdownMenuTrigger
              render={
                <Button variant="outline" size="sm" aria-label="Export history" />
              }
            >
              <Download className="mr-1.5 h-4 w-4" />
              Export
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onClick={() => { exportToCsv(); showInfo("Exported as CSV"); }}>
                <FileSpreadsheet className="mr-2 h-4 w-4" />
                Export as CSV
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => { exportToJson(); showInfo("Exported as JSON"); }}>
                <FileJson className="mr-2 h-4 w-4" />
                Export as JSON
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>

          {/* Clear all — confirmation dialog */}
          <Dialog>
            <DialogTrigger
              render={
                <Button variant="destructive" size="sm" aria-label="Clear all history" />
              }
            >
              <Trash2 className="mr-1.5 h-4 w-4" />
              Clear All
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Clear Analysis History</DialogTitle>
                <DialogDescription>
                  This will permanently delete all {entries.length} analysis
                  result{entries.length !== 1 ? "s" : ""} from your local
                  storage. This action cannot be undone.
                </DialogDescription>
              </DialogHeader>
              <DialogFooter>
                <DialogClose render={<Button variant="outline" />}>
                  Cancel
                </DialogClose>
                <DialogClose
                  render={<Button variant="destructive" />}
                  onClick={handleClearAll}
                >
                  <Trash2 className="mr-1.5 h-4 w-4" />
                  Delete All
                </DialogClose>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>
        </div>
        </FadeIn>

        {/* Data table */}
        <FadeIn delay={0.15}>
          <HistoryTable
            data={entries}
            onView={handleView}
            onReanalyse={handleReanalyse}
            onDelete={handleDelete}
          />
        </FadeIn>
      </div>
    </PageTransition>
  );
}
