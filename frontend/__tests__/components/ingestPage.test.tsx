/**
 * Tests for the EML Ingestion page (`app/(app)/analyze/ingest/page.tsx`).
 *
 * Covers:
 * 1. No file selected -> the Analyse button is disabled and no upload fires.
 * 2. Selecting a .eml file and submitting renders the parsed summary
 *    (subject, sender, recipients, attachments) plus the verdict banner.
 * 3. A backend error (e.g. 422 "no readable body") renders inline.
 */

import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import EmlIngestPage from "@/app/(app)/analyze/ingest/page";
import { ingestEmail } from "@/lib/api/endpoints";
import { safeResponse } from "../fixtures";
import type { EmailIngestResponse } from "@/types";

/* ------------------------------------------------------------------ */
/*  Mocks                                                             */
/* ------------------------------------------------------------------ */

jest.mock("@/lib/api/endpoints", () => ({
  ingestEmail: jest.fn(),
}));

jest.mock("@/lib/toast", () => ({
  showError: jest.fn(),
  showInfo: jest.fn(),
  showSuccess: jest.fn(),
  showWarning: jest.fn(),
  showPromise: jest.fn(),
}));

const mockIngestEmail = ingestEmail as jest.Mock;

beforeEach(() => {
  mockIngestEmail.mockReset();
});

/* ------------------------------------------------------------------ */
/*  Fixtures                                                          */
/* ------------------------------------------------------------------ */

function ingestResponse(overrides: Partial<EmailIngestResponse> = {}): EmailIngestResponse {
  return {
    ...safeResponse,
    parsed: {
      subject: "Security Alert",
      senderName: "",
      senderAddress: "security@paypa1-support.com",
      recipients: ["victim@example.com"],
      bodyPreview: "Urgent! Your account has been suspended.",
      hasAttachments: true,
      attachmentNames: ["invoice.pdf"],
      sizeBytes: 512,
    },
    ...overrides,
  } as EmailIngestResponse;
}

function selectFile() {
  render(<EmlIngestPage />);
  const input = screen.getByTestId("eml-file-input");
  const file = new File(["From: a@b.c\nSubject: Hi\n\nBody"], "phish.eml", {
    type: "message/rfc822",
  });
  fireEvent.change(input, { target: { files: [file] } });
  return file;
}

/* ------------------------------------------------------------------ */
/*  Upload gate                                                       */
/* ------------------------------------------------------------------ */

it("disables the Analyse button until a file is selected", () => {
  render(<EmlIngestPage />);
  const analyse = screen.getByRole("button", { name: "Analyse email" });
  expect(analyse).toBeDisabled();
  expect(mockIngestEmail).not.toHaveBeenCalled();
});

/* ------------------------------------------------------------------ */
/*  Happy path                                                        */
/* ------------------------------------------------------------------ */

it("uploads the file and renders the parsed summary and verdict", async () => {
  mockIngestEmail.mockResolvedValue(ingestResponse());

  const file = selectFile();
  fireEvent.click(screen.getByRole("button", { name: "Analyse email" }));

  await waitFor(() => {
    expect(mockIngestEmail).toHaveBeenCalledWith(file);
  });

  // Parsed summary block
  expect(screen.getByText("Security Alert")).toBeInTheDocument();
  expect(screen.getByText("security@paypa1-support.com")).toBeInTheDocument();
  expect(screen.getByText("victim@example.com")).toBeInTheDocument();
  expect(screen.getByText("invoice.pdf")).toBeInTheDocument();

  // Verdict banner (from the fixture: safe — labelled "Not phishing").
  await waitFor(() => {
    expect(screen.getByLabelText("Not phishing")).toBeInTheDocument();
  });
});

it("renders the file name and size after selection", () => {
  const file = selectFile();
  expect(screen.getByText("phish.eml")).toBeInTheDocument();
  // The page formats the real byte size of the selected file.
  expect(screen.getByText(`${file.size} B`)).toBeInTheDocument();
});

/* ------------------------------------------------------------------ */
/*  Error path                                                        */
/* ------------------------------------------------------------------ */

it("renders an inline error when the backend rejects the file", async () => {
  mockIngestEmail.mockRejectedValue(
    new Error("No readable text body found in the .eml payload"),
  );

  selectFile();
  fireEvent.click(screen.getByRole("button", { name: "Analyse email" }));

  await waitFor(() => {
    expect(
      screen.getByText("No readable text body found in the .eml payload"),
    ).toBeInTheDocument();
  });
  // The banner must not appear on failure.
  expect(screen.queryByText(/parsed from the file/i)).not.toBeInTheDocument();
});
