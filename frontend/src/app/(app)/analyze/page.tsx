import type { Metadata } from "next";
import { Search } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export const metadata: Metadata = {
  title: "Analyse",
};

/**
 * Analyse page — placeholder for the URL / email / text analysis form.
 * Will be fully implemented in Issue #30 (Analyze page).
 */
export default function AnalyzePage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Analyse Content</h1>
        <p className="text-muted-foreground">
          Submit a URL, email, or text to detect phishing threats.
        </p>
      </div>

      <Card>
        <CardHeader className="items-center text-center">
          <div className="rounded-full border bg-muted p-4">
            <Search className="h-8 w-8 text-muted-foreground" />
          </div>
          <CardTitle>Analysis Form</CardTitle>
          <CardDescription>
            The full analysis form with URL, email, and text input modes
            will be built in an upcoming issue.
          </CardDescription>
        </CardHeader>
        <CardContent className="text-center text-sm text-muted-foreground">
          <p>Coming soon — stay tuned!</p>
        </CardContent>
      </Card>
    </div>
  );
}
