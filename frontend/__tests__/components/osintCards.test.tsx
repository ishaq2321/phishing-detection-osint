/**
 * Tests for the OsintCards component.
 *
 * Verifies domain info, DNS status, and reputation cards render
 * correctly for both available and null OSINT data.
 */

import React from "react";
import { render, screen } from "@testing-library/react";
import { OsintCards } from "@/components/results/osintCards";
import { safeOsint, suspiciousOsint } from "../fixtures";

/* ------------------------------------------------------------------ */
/*  Tooltip mock — base-ui Tooltip requires popper/portal             */
/* ------------------------------------------------------------------ */

jest.mock("@/components/ui/tooltip", () => ({
  Tooltip: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  TooltipTrigger: ({ children }: { children: React.ReactNode }) => <span>{children}</span>,
  TooltipContent: ({ children }: { children: React.ReactNode }) => <span>{children}</span>,
}));

/* ------------------------------------------------------------------ */
/*  Progress mock — avoid SVG rendering issues in jsdom               */
/* ------------------------------------------------------------------ */

jest.mock("@/components/ui/progress", () => ({
  Progress: ({ children, ...props }: React.PropsWithChildren<Record<string, unknown>>) => (
    <div data-testid="progress" {...props}>{children}</div>
  ),
  ProgressTrack: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  ProgressIndicator: (props: Record<string, unknown>) => <div data-testid="progress-indicator" {...props} />,
}));

/* ------------------------------------------------------------------ */
/*  With OSINT data                                                   */
/* ------------------------------------------------------------------ */

describe("OsintCards — with data", () => {
  beforeEach(() => {
    render(<OsintCards osint={safeOsint} />);
  });

  it("renders the domain name", () => {
    expect(screen.getByText("example.com")).toBeInTheDocument();
  });

  it("shows the registrar", () => {
    expect(screen.getByText("MarkMonitor Inc.")).toBeInTheDocument();
  });

  it("renders all three section headers", () => {
    expect(screen.getByText("Domain Information")).toBeInTheDocument();
    expect(screen.getByText("DNS Status")).toBeInTheDocument();
    expect(screen.getByText("Reputation")).toBeInTheDocument();
  });

  it("shows the DNS status as valid", () => {
    expect(screen.getByText("Valid DNS")).toBeInTheDocument();
  });

  it("shows privacy status as public", () => {
    expect(screen.getByText("Public")).toBeInTheDocument();
  });

  it("shows not in blacklists", () => {
    expect(screen.getByText("Clean")).toBeInTheDocument();
  });
});

/* ------------------------------------------------------------------ */
/*  Suspicious OSINT data                                             */
/* ------------------------------------------------------------------ */

describe("OsintCards — suspicious data", () => {
  beforeEach(() => {
    render(<OsintCards osint={suspiciousOsint} />);
  });

  it("shows the suspicious domain", () => {
    expect(screen.getByText("examp1e-login.tk")).toBeInTheDocument();
  });

  it("shows private registration", () => {
    expect(screen.getByText("Protected")).toBeInTheDocument();
  });
});

/* ------------------------------------------------------------------ */
/*  Null OSINT data                                                   */
/* ------------------------------------------------------------------ */

describe("OsintCards — null data", () => {
  it("renders a fallback message when osint is null", () => {
    render(<OsintCards osint={null} />);
    expect(
      screen.getByText("OSINT Data Not Available"),
    ).toBeInTheDocument();
  });
});
