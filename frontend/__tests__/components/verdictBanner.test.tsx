/**
 * Tests for the VerdictBanner component.
 *
 * Verifies correct rendering for each threat level: safe, suspicious,
 * dangerous, and critical.
 */

import React from "react";
import { render, screen } from "@testing-library/react";
import { VerdictBanner } from "@/components/results/verdictBanner";
import {
  safeVerdict,
  suspiciousVerdict,
  dangerousVerdict,
  criticalVerdict,
} from "../fixtures";

/* ------------------------------------------------------------------ */
/*  Mock hooks that cause issues in test environment                  */
/* ------------------------------------------------------------------ */

jest.mock("@/hooks/useCountUp", () => ({
  useCountUp: (target: number) => target,
}));

/* ------------------------------------------------------------------ */
/*  Safe verdict                                                      */
/* ------------------------------------------------------------------ */

describe("VerdictBanner — safe", () => {
  beforeEach(() => {
    render(<VerdictBanner verdict={safeVerdict} />);
  });

  it("displays 'Safe' status text", () => {
    expect(screen.getByText("Safe")).toBeInTheDocument();
  });

  it("shows the confidence score", () => {
    expect(screen.getByText("15")).toBeInTheDocument();
  });

  it("shows the recommendation", () => {
    expect(
      screen.getByText("This content appears to be safe."),
    ).toBeInTheDocument();
  });

  it("displays a threat level badge", () => {
    expect(screen.getByText(/✅.*Safe/)).toBeInTheDocument();
  });
});

/* ------------------------------------------------------------------ */
/*  Suspicious verdict                                                */
/* ------------------------------------------------------------------ */

describe("VerdictBanner — suspicious", () => {
  beforeEach(() => {
    render(<VerdictBanner verdict={suspiciousVerdict} />);
  });

  it("displays 'Safe' (not phishing) status text", () => {
    expect(screen.getByText("Safe")).toBeInTheDocument();
  });

  it("shows the confidence score", () => {
    expect(screen.getByText("55")).toBeInTheDocument();
  });

  it("shows suspicious badge", () => {
    expect(screen.getByText(/⚠️.*Suspicious/)).toBeInTheDocument();
  });
});

/* ------------------------------------------------------------------ */
/*  Dangerous verdict                                                 */
/* ------------------------------------------------------------------ */

describe("VerdictBanner — dangerous", () => {
  beforeEach(() => {
    render(<VerdictBanner verdict={dangerousVerdict} />);
  });

  it("displays 'Phishing' status text", () => {
    expect(screen.getByText("Phishing")).toBeInTheDocument();
  });

  it("shows the confidence score", () => {
    expect(screen.getByText("78")).toBeInTheDocument();
  });

  it("shows the recommendation", () => {
    expect(
      screen.getByText("Do not interact with this content."),
    ).toBeInTheDocument();
  });
});

/* ------------------------------------------------------------------ */
/*  Critical verdict                                                  */
/* ------------------------------------------------------------------ */

describe("VerdictBanner — critical", () => {
  beforeEach(() => {
    render(<VerdictBanner verdict={criticalVerdict} />);
  });

  it("displays 'Phishing' status text", () => {
    expect(screen.getByText("Phishing")).toBeInTheDocument();
  });

  it("shows the confidence score", () => {
    expect(screen.getByText("95")).toBeInTheDocument();
  });

  it("shows critical badge", () => {
    expect(screen.getByText(/🚨.*Critical/)).toBeInTheDocument();
  });
});

/* ------------------------------------------------------------------ */
/*  Accessibility                                                     */
/* ------------------------------------------------------------------ */

describe("VerdictBanner — accessibility", () => {
  it("has aria-label for phishing detected", () => {
    render(<VerdictBanner verdict={dangerousVerdict} />);
    expect(screen.getByLabelText("Phishing detected")).toBeInTheDocument();
  });

  it("has aria-label for not phishing", () => {
    render(<VerdictBanner verdict={safeVerdict} />);
    expect(screen.getByLabelText("Not phishing")).toBeInTheDocument();
  });

  it("has aria-label for confidence score", () => {
    render(<VerdictBanner verdict={safeVerdict} />);
    expect(
      screen.getByLabelText("Confidence score: 15 percent"),
    ).toBeInTheDocument();
  });
});
