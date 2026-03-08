/**
 * Tests for lib/toast.ts — toast notification helpers.
 */

import { showSuccess, showError, showWarning, showInfo, showPromise } from "@/lib/toast";
import { toast } from "sonner";

jest.mock("sonner", () => ({
  toast: {
    success: jest.fn(),
    error: jest.fn(),
    warning: jest.fn(),
    info: jest.fn(),
    promise: jest.fn(),
  },
}));

describe("showSuccess", () => {
  it("calls toast.success with message", () => {
    showSuccess("Done!");
    expect(toast.success).toHaveBeenCalledWith("Done!", { description: undefined });
  });

  it("passes the description", () => {
    showSuccess("Done!", "Extra info");
    expect(toast.success).toHaveBeenCalledWith("Done!", { description: "Extra info" });
  });
});

describe("showError", () => {
  it("calls toast.error with message", () => {
    showError("Failed!");
    expect(toast.error).toHaveBeenCalledWith("Failed!", { description: undefined });
  });
});

describe("showWarning", () => {
  it("calls toast.warning with message", () => {
    showWarning("Careful!");
    expect(toast.warning).toHaveBeenCalledWith("Careful!", { description: undefined });
  });
});

describe("showInfo", () => {
  it("calls toast.info with message", () => {
    showInfo("FYI");
    expect(toast.info).toHaveBeenCalledWith("FYI", { description: undefined });
  });
});

describe("showPromise", () => {
  it("calls toast.promise with the promise and messages", () => {
    const p = Promise.resolve("ok");
    const msgs = { loading: "Loading...", success: "Done!", error: "Failed!" };
    showPromise(p, msgs);
    expect(toast.promise).toHaveBeenCalledWith(p, msgs);
  });
});
