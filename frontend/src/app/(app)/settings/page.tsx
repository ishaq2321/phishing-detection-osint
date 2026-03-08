import type { Metadata } from "next";
import { Settings } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export const metadata: Metadata = {
  title: "Settings",
};

/**
 * Settings page — placeholder for API config, display preferences,
 * and history management.  Full implementation in Issue #45.
 */
export default function SettingsPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Settings</h1>
        <p className="text-muted-foreground">
          Configure API connection, display preferences, and history
          management.
        </p>
      </div>

      <Card>
        <CardHeader className="items-center text-center">
          <div className="rounded-full border bg-muted p-4">
            <Settings className="h-8 w-8 text-muted-foreground" />
          </div>
          <CardTitle>Application Settings</CardTitle>
          <CardDescription>
            API configuration, theme preferences, history controls, and
            about section will be built in an upcoming issue.
          </CardDescription>
        </CardHeader>
        <CardContent className="text-center text-sm text-muted-foreground">
          <p>Coming soon — stay tuned!</p>
        </CardContent>
      </Card>
    </div>
  );
}
