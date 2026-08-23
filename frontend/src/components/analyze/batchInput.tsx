"use client";

/**
 * BatchInput — textarea for entering multiple URLs (one per line) or
 * uploading a .txt / .csv file.
 */

import { useMemo, useRef, type ChangeEvent } from "react";
import { Upload, Link2, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { validateBatch } from "@/lib/validation";

const MAX_URLS = 50;

interface BatchInputProps {
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
}

export function BatchInput({ value, onChange, disabled }: BatchInputProps) {
  const fileRef = useRef<HTMLInputElement>(null);

  const { valid, invalid } = useMemo(() => validateBatch(value), [value]);

  function handleFile(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = () => {
      const text = reader.result as string;
      onChange(text.trim());
    };
    reader.readAsText(file);

    // Reset file input so the same file can be re-uploaded
    e.target.value = "";
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Link2 className="h-5 w-5" aria-hidden="true" />
          URL List
        </CardTitle>
        <CardDescription>
          Enter up to {MAX_URLS} URLs, one per line, or upload a file.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <Textarea
          id="batch-urls"
          placeholder={
            "https://example.com\nhttps://suspicious-site.xyz/login\nhttps://phishy-bank.tk/verify"
          }
          className="min-h-[200px] font-mono text-sm"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          disabled={disabled}
          aria-label="URLs to analyse (one per line)"
        />

        {invalid.length > 0 && (
          <p className="text-xs text-destructive" role="alert">
            {invalid.length} line{invalid.length !== 1 ? "s" : ""} will be
            skipped — not valid http(s) URLs (e.g. missing https://).
          </p>
        )}

        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">
            {valid.length} / {MAX_URLS} valid URLs
            {invalid.length > 0 && ` · ${invalid.length} invalid`}
            {valid.length > MAX_URLS && (
              <span className="ml-1 text-destructive font-medium">
                (max {MAX_URLS})
              </span>
            )}
          </span>

          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => onChange("")}
              disabled={disabled || !value}
            >
              <X className="mr-1 h-3 w-3" aria-hidden="true" />
              Clear
            </Button>

            <Button
              variant="outline"
              size="sm"
              onClick={() => fileRef.current?.click()}
              disabled={disabled}
            >
              <Upload className="mr-1 h-3 w-3" aria-hidden="true" />
              Upload File
            </Button>

            <input
              ref={fileRef}
              type="file"
              accept=".txt,.csv"
              className="hidden"
              onChange={handleFile}
            />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
