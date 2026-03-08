/**
 * Tests for the FeatureCards component.
 *
 * Verifies feature counts and detected tactics render correctly.
 */

import React from "react";
import { render, screen } from "@testing-library/react";
import { FeatureCards } from "@/components/results/featureCards";
import { safeFeatures, dangerousFeatures } from "../fixtures";

/* ------------------------------------------------------------------ */
/*  Mock animated count-up hook                                       */
/* ------------------------------------------------------------------ */

jest.mock("@/hooks/useCountUp", () => ({
  useCountUp: (target: number) => target,
}));

/* ------------------------------------------------------------------ */
/*  Tooltip mock                                                      */
/* ------------------------------------------------------------------ */

jest.mock("@/components/ui/tooltip", () => ({
  Tooltip: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  TooltipTrigger: ({ children }: { children: React.ReactNode }) => <span>{children}</span>,
  TooltipContent: ({ children }: { children: React.ReactNode }) => <span>{children}</span>,
}));

/* ------------------------------------------------------------------ */
/*  With many features (dangerous)                                    */
/* ------------------------------------------------------------------ */

describe("FeatureCards — dangerous features", () => {
  beforeEach(() => {
    render(<FeatureCards features={dangerousFeatures} />);
  });

  it("renders the feature counts card", () => {
    expect(screen.getByText("Extracted Features")).toBeInTheDocument();
  });

  it("displays URL feature count", () => {
    expect(screen.getByText("5")).toBeInTheDocument();
  });

  it("displays total risk indicators", () => {
    expect(screen.getByText("12")).toBeInTheDocument();
  });

  it("renders detected tactic badges", () => {
    expect(screen.getByText("Urgency")).toBeInTheDocument();
    expect(screen.getByText("Brand Impersonation")).toBeInTheDocument();
    expect(screen.getByText("Credential Request")).toBeInTheDocument();
  });
});

/* ------------------------------------------------------------------ */
/*  With safe features                                                */
/* ------------------------------------------------------------------ */

describe("FeatureCards — safe features", () => {
  beforeEach(() => {
    render(<FeatureCards features={safeFeatures} />);
  });

  it("shows low feature counts", () => {
    expect(screen.getAllByText("0")[0]).toBeInTheDocument(); // url features
    expect(screen.getAllByText("1")[0]).toBeInTheDocument(); // text features
  });

  it("shows empty tactics state", () => {
    expect(
      screen.getByText(/no suspicious tactics detected/i),
    ).toBeInTheDocument();
  });
});
