"use client";

/**
 * HistoryTable — TanStack Table-powered data table for analysis
 * history entries.
 *
 * Features:
 * - Sortable columns (click header)
 * - Global search across content
 * - Threat-level filter dropdown
 * - Page-size selector (10 / 25 / 50)
 * - Row actions: view results, re-analyse, delete
 */

import { useCallback, useMemo, useState } from "react";
import {
  type ColumnDef,
  type ColumnFiltersState,
  type SortingState,
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
} from "@tanstack/react-table";
import {
  ArrowUpDown,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Eye,
  MoreHorizontal,
  RefreshCw,
  Trash2,
} from "lucide-react";
import type { ThreatLevel } from "@/types";
import type { LucideIcon } from "lucide-react";
import type { HistoryEntry } from "@/lib/storage/historyStore";
import { THREAT_LEVEL_MAP } from "@/lib/constants";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

/* ------------------------------------------------------------------ */
/*  Threat-level badge colour map                                     */
/* ------------------------------------------------------------------ */

const BADGE_COLOUR: Record<ThreatLevel, string> = {
  safe: "bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-400",
  suspicious:
    "bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-400",
  dangerous:
    "bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-400",
  critical: "bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-400",
};

/* ------------------------------------------------------------------ */
/*  Column definitions                                                */
/* ------------------------------------------------------------------ */

function buildColumns(
  onView: (entry: HistoryEntry) => void,
  onReanalyse: (entry: HistoryEntry) => void,
  onDelete: (entry: HistoryEntry) => void,
): ColumnDef<HistoryEntry>[] {
  return [
    /* # (row number) */
    {
      id: "index",
      header: "#",
      cell: ({ row }) => (
        <span className="text-muted-foreground tabular-nums">
          {row.index + 1}
        </span>
      ),
      enableSorting: false,
      size: 48,
    },

    /* Content (truncated) */
    {
      accessorKey: "content",
      header: ({ column }) => (
        <Button
          variant="ghost"
          size="sm"
          onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}
          className="-ml-2"
        >
          Content
          <ArrowUpDown className="ml-1 h-3.5 w-3.5" />
        </Button>
      ),
      cell: ({ getValue }) => {
        const value = getValue<string>();
        const truncated =
          value.length > 60 ? `${value.slice(0, 57)}…` : value;
        return (
          <span className="max-w-[260px] truncate font-mono text-xs" title={value}>
            {truncated}
          </span>
        );
      },
    },

    /* Type */
    {
      accessorKey: "contentType",
      header: "Type",
      cell: ({ getValue }) => (
        <Badge variant="outline" className="capitalize">
          {getValue<string>()}
        </Badge>
      ),
      size: 90,
    },

    /* Threat Level */
    {
      accessorKey: "threatLevel",
      header: ({ column }) => (
        <Button
          variant="ghost"
          size="sm"
          onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}
          className="-ml-2"
        >
          Threat Level
          <ArrowUpDown className="ml-1 h-3.5 w-3.5" />
        </Button>
      ),
      cell: ({ getValue }) => {
        const level = getValue<ThreatLevel>();
        const meta = THREAT_LEVEL_MAP[level];
        const LevelIcon = meta.icon;
        return (
          <Badge
            variant="secondary"
            className={BADGE_COLOUR[level]}
          >
            <LevelIcon className="mr-1 h-3 w-3" aria-hidden="true" /> {meta.label}
          </Badge>
        );
      },
      filterFn: "equals",
      size: 130,
    },

    /* Score */
    {
      accessorKey: "score",
      header: ({ column }) => (
        <Button
          variant="ghost"
          size="sm"
          onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}
          className="-ml-2"
        >
          Score
          <ArrowUpDown className="ml-1 h-3.5 w-3.5" />
        </Button>
      ),
      cell: ({ getValue }) => (
        <span className="tabular-nums font-medium">
          {(getValue<number>() * 100).toFixed(1)}%
        </span>
      ),
      size: 80,
    },

    /* Date */
    {
      accessorKey: "analyzedAt",
      header: ({ column }) => (
        <Button
          variant="ghost"
          size="sm"
          onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}
          className="-ml-2"
        >
          Date
          <ArrowUpDown className="ml-1 h-3.5 w-3.5" />
        </Button>
      ),
      cell: ({ getValue }) => {
        const date = new Date(getValue<string>());
        return (
          <span className="text-muted-foreground text-xs tabular-nums">
            {date.toLocaleDateString(undefined, {
              year: "numeric",
              month: "short",
              day: "numeric",
            })}{" "}
            {date.toLocaleTimeString(undefined, {
              hour: "2-digit",
              minute: "2-digit",
            })}
          </span>
        );
      },
      size: 160,
    },

    /* Actions */
    {
      id: "actions",
      header: () => <span className="sr-only">Actions</span>,
      cell: ({ row }) => {
        const entry = row.original;
        return (
          <DropdownMenu>
            <DropdownMenuTrigger
              render={
                <Button variant="ghost" size="icon-sm" aria-label="Row actions" />
              }
            >
              <MoreHorizontal className="h-4 w-4" />
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onClick={() => onView(entry)}>
                <Eye className="mr-2 h-4 w-4" />
                View Results
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => onReanalyse(entry)}>
                <RefreshCw className="mr-2 h-4 w-4" />
                Re-analyse
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                variant="destructive"
                onClick={() => onDelete(entry)}
              >
                <Trash2 className="mr-2 h-4 w-4" />
                Delete
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        );
      },
      size: 48,
    },
  ];
}

/* ------------------------------------------------------------------ */
/*  Mobile card view                                                  */
/* ------------------------------------------------------------------ */

function MobileCard({
  entry,
  index,
  onView,
  onReanalyse,
  onDelete,
}: {
  entry: HistoryEntry;
  index: number;
  onView: (e: HistoryEntry) => void;
  onReanalyse: (e: HistoryEntry) => void;
  onDelete: (e: HistoryEntry) => void;
}) {
  const meta = THREAT_LEVEL_MAP[entry.threatLevel];
  const LevelIcon = meta.icon;
  const date = new Date(entry.analyzedAt);

  return (
    <div className="rounded-lg border bg-card p-4 space-y-3">
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <span className="text-xs text-muted-foreground tabular-nums">
            #{index + 1}
          </span>
          <Badge variant="outline" className="capitalize shrink-0">
            {entry.contentType}
          </Badge>
        </div>
        <Badge variant="secondary" className={BADGE_COLOUR[entry.threatLevel]}>
          <LevelIcon className="mr-1 h-3 w-3" aria-hidden="true" /> {meta.label}
        </Badge>
      </div>

      <p
        className="font-mono text-xs text-foreground truncate"
        title={entry.content}
      >
        {entry.content.length > 60
          ? `${entry.content.slice(0, 57)}…`
          : entry.content}
      </p>

      <div className="flex items-center justify-between text-xs text-muted-foreground">
        <span className="tabular-nums font-medium text-foreground">
          Score: {(entry.score * 100).toFixed(1)}%
        </span>
        <span className="tabular-nums">
          {date.toLocaleDateString(undefined, {
            month: "short",
            day: "numeric",
            year: "numeric",
          })}
        </span>
      </div>

      <div className="flex gap-2 pt-1">
        <Button variant="outline" size="sm" className="flex-1" onClick={() => onView(entry)}>
          <Eye className="mr-1 h-3.5 w-3.5" />
          View
        </Button>
        <Button variant="outline" size="sm" className="flex-1" onClick={() => onReanalyse(entry)}>
          <RefreshCw className="mr-1 h-3.5 w-3.5" />
          Re-analyse
        </Button>
        <Button variant="destructive" size="icon-sm" onClick={() => onDelete(entry)} aria-label="Delete entry">
          <Trash2 className="h-3.5 w-3.5" />
        </Button>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Threat-level filter options                                       */
/* ------------------------------------------------------------------ */

const THREAT_FILTER_OPTIONS: { value: string; label: string; icon?: LucideIcon }[] = [
  { value: "all", label: "All Levels" },
  { value: "safe", label: "Safe", icon: THREAT_LEVEL_MAP.safe.icon },
  { value: "suspicious", label: "Suspicious", icon: THREAT_LEVEL_MAP.suspicious.icon },
  { value: "dangerous", label: "Dangerous", icon: THREAT_LEVEL_MAP.dangerous.icon },
  { value: "critical", label: "Critical", icon: THREAT_LEVEL_MAP.critical.icon },
];

/* ------------------------------------------------------------------ */
/*  Component                                                         */
/* ------------------------------------------------------------------ */

export interface HistoryTableProps {
  data: HistoryEntry[];
  onView: (entry: HistoryEntry) => void;
  onReanalyse: (entry: HistoryEntry) => void;
  onDelete: (entry: HistoryEntry) => void;
}

export function HistoryTable({
  data,
  onView,
  onReanalyse,
  onDelete,
}: HistoryTableProps) {
  "use no memo";
  const [sorting, setSorting] = useState<SortingState>([]);
  const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>([]);
  const [globalFilter, setGlobalFilter] = useState("");

  const columns = useMemo(
    () => buildColumns(onView, onReanalyse, onDelete),
    [onView, onReanalyse, onDelete],
  );

  /* TanStack Table returns mutable refs — "use no memo" above opts out
     of React Compiler memoisation for this component. */
  // eslint-disable-next-line react-hooks/incompatible-library
  const table = useReactTable({
    data,
    columns,
    state: { sorting, columnFilters, globalFilter },
    onSortingChange: setSorting,
    onColumnFiltersChange: setColumnFilters,
    onGlobalFilterChange: setGlobalFilter,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    initialState: { pagination: { pageSize: 10 } },
  });

  const handleThreatFilter = useCallback(
    (value: string | null) => {
      if (!value || value === "all") {
        table.getColumn("threatLevel")?.setFilterValue(undefined);
      } else {
        table.getColumn("threatLevel")?.setFilterValue(value);
      }
    },
    [table],
  );

  /* ── Toolbar ───────────────────────────────────────────────────── */
  const toolbar = (
    <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
      {/* Search */}
      <Input
        placeholder="Search content or domain…"
        value={globalFilter}
        onChange={(e) => setGlobalFilter(e.target.value)}
        className="max-w-sm"
        aria-label="Search analysis history"
      />

      {/* Threat-level filter */}
      <Select
        defaultValue="all"
        onValueChange={handleThreatFilter}
      >
        <SelectTrigger className="w-[160px]" aria-label="Filter by threat level">
          <SelectValue placeholder="Filter by level" />
        </SelectTrigger>
        <SelectContent>
          <SelectGroup>
            {THREAT_FILTER_OPTIONS.map((opt) => {
              const FilterIcon = opt.icon;
              return (
                <SelectItem key={opt.value} value={opt.value}>
                  <span className="flex items-center gap-1.5">
                    {FilterIcon && <FilterIcon className="h-3.5 w-3.5" />}
                    {opt.label}
                  </span>
                </SelectItem>
              );
            })}
          </SelectGroup>
        </SelectContent>
      </Select>
    </div>
  );

  /* ── Pagination controls ───────────────────────────────────────── */
  const pagination = (
    <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
      <p className="text-sm text-muted-foreground">
        {table.getFilteredRowModel().rows.length} result
        {table.getFilteredRowModel().rows.length !== 1 ? "s" : ""}
      </p>

      <div className="flex items-center gap-2">
        {/* Page-size selector */}
        <div className="flex items-center gap-1.5 text-sm text-muted-foreground">
          <span>Rows</span>
          <Select
            defaultValue="10"
            onValueChange={(v) => {
              if (v) table.setPageSize(Number(v));
            }}
          >
            <SelectTrigger className="w-[70px]" size="sm" aria-label="Rows per page">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                {[10, 25, 50].map((size) => (
                  <SelectItem key={size} value={String(size)}>
                    {size}
                  </SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
        </div>

        {/* Page navigation */}
        <div className="flex items-center gap-1">
          <Button
            variant="outline"
            size="icon-sm"
            onClick={() => table.firstPage()}
            disabled={!table.getCanPreviousPage()}
            aria-label="First page"
          >
            <ChevronsLeft className="h-4 w-4" />
          </Button>
          <Button
            variant="outline"
            size="icon-sm"
            onClick={() => table.previousPage()}
            disabled={!table.getCanPreviousPage()}
            aria-label="Previous page"
          >
            <ChevronLeft className="h-4 w-4" />
          </Button>

          <span className="px-2 text-sm tabular-nums text-muted-foreground">
            {table.getState().pagination.pageIndex + 1} / {table.getPageCount()}
          </span>

          <Button
            variant="outline"
            size="icon-sm"
            onClick={() => table.nextPage()}
            disabled={!table.getCanNextPage()}
            aria-label="Next page"
          >
            <ChevronRight className="h-4 w-4" />
          </Button>
          <Button
            variant="outline"
            size="icon-sm"
            onClick={() => table.lastPage()}
            disabled={!table.getCanNextPage()}
            aria-label="Last page"
          >
            <ChevronsRight className="h-4 w-4" />
          </Button>
        </div>
      </div>
    </div>
  );

  /* ── Desktop table ─────────────────────────────────────────────── */
  const desktopTable = (
    <div className="hidden md:block rounded-lg border">
      <Table>
        <TableHeader>
          {table.getHeaderGroups().map((headerGroup) => (
            <TableRow key={headerGroup.id}>
              {headerGroup.headers.map((header) => (
                <TableHead
                  key={header.id}
                  style={{ width: header.column.getSize() }}
                >
                  {header.isPlaceholder
                    ? null
                    : flexRender(
                        header.column.columnDef.header,
                        header.getContext(),
                      )}
                </TableHead>
              ))}
            </TableRow>
          ))}
        </TableHeader>
        <TableBody>
          {table.getRowModel().rows.length ? (
            table.getRowModel().rows.map((row) => (
              <TableRow key={row.id}>
                {row.getVisibleCells().map((cell) => (
                  <TableCell key={cell.id}>
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </TableCell>
                ))}
              </TableRow>
            ))
          ) : (
            <TableRow>
              <TableCell
                colSpan={columns.length}
                className="h-24 text-center text-muted-foreground"
              >
                No results found.
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
    </div>
  );

  /* ── Mobile cards ──────────────────────────────────────────────── */
  const mobileCards = (
    <div className="md:hidden space-y-3">
      {table.getRowModel().rows.length ? (
        table.getRowModel().rows.map((row) => (
          <MobileCard
            key={row.id}
            entry={row.original}
            index={row.index}
            onView={onView}
            onReanalyse={onReanalyse}
            onDelete={onDelete}
          />
        ))
      ) : (
        <p className="py-8 text-center text-sm text-muted-foreground">
          No results found.
        </p>
      )}
    </div>
  );

  return (
    <div className="space-y-4">
      {toolbar}
      {desktopTable}
      {mobileCards}
      {pagination}
    </div>
  );
}
