import type { Metadata } from "next";
import { History } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export const metadata: Metadata = {
  title: "History",
};

/**
 * History page — placeholder for the analysis history data table.
 * Will be fully implemented in Issue #36.
 */
export default function HistoryPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Analysis History</h1>
        <p className="text-muted-foreground">
          Review and manage your past analysis results.
        </p>
      </div>

      <Card>
        <CardHeader className="items-center text-center">
          <div className="rounded-full border bg-muted p-4">
            <History className="h-8 w-8 text-muted-foreground" />
          </div>
          <CardTitle>No Analyses Yet</CardTitle>
          <CardDescription>
            Your analysis history will appear here once you start
            analysing URLs, emails, or text.
          </CardDescription>
        </CardHeader>
        <CardContent className="text-center text-sm text-muted-foreground">
          <p>History table with sorting, filtering, and export — coming soon.</p>
        </CardContent>
      </Card>
    </div>
  );
}
