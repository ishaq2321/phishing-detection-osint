/**
 * Tests for the VerdictFeedback component.
 *
 * Covers the operator feedback loop UI:
 * 1. Renders nothing without a history ID (backend requires one).
 * 2. Posts the selected label to POST /api/feedback.
 * 3. Shows a confirmation state after success and an error state on failure.
 */

import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { VerdictFeedback } from "@/components/results/verdictFeedback";
import { submitFeedback } from "@/lib/api/endpoints";

jest.mock("@/lib/api/endpoints", () => ({
  submitFeedback: jest.fn(),
}));

const mockSubmit = submitFeedback as jest.Mock;

beforeEach(() => {
  mockSubmit.mockReset();
});

describe("VerdictFeedback", () => {
  it("renders nothing when historyId is missing", () => {
    const { container } = render(<VerdictFeedback />);
    expect(container).toBeEmptyDOMElement();
    expect(mockSubmit).not.toHaveBeenCalled();
  });

  it("submits the chosen label with the history id", async () => {
    mockSubmit.mockResolvedValueOnce({ accepted: true, feedbackId: "fb-1", historyId: "abc-123" });
    render(<VerdictFeedback historyId="abc-123" />);

    fireEvent.click(screen.getByRole("button", { name: /correct/i }));

    await waitFor(() => {
      expect(mockSubmit).toHaveBeenCalledWith({
        historyId: "abc-123",
        verdict: "correct",
      });
    });
    expect(
      await screen.findByText(/your label was recorded/i),
    ).toBeInTheDocument();
  });

  it("sends false_positive when the user flags a bad verdict", async () => {
    mockSubmit.mockResolvedValueOnce({ accepted: true, feedbackId: "fb-2", historyId: "abc-123" });
    render(<VerdictFeedback historyId="abc-123" />);

    fireEvent.click(
      screen.getByRole("button", { name: /false positive/i }),
    );

    await waitFor(() => {
      expect(mockSubmit).toHaveBeenCalledWith({
        historyId: "abc-123",
        verdict: "false_positive",
      });
    });
  });

  it("shows an error message when submission fails", async () => {
    mockSubmit.mockRejectedValueOnce(new Error("network down"));
    render(<VerdictFeedback historyId="abc-123" />);

    fireEvent.click(screen.getByRole("button", { name: /missed phishing/i }));

    expect(
      await screen.findByText(/could not record feedback/i),
    ).toBeInTheDocument();
  });
});
