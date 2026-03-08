/**
 * Tests for lib/storage/historyStore.ts — localStorage-backed history CRUD.
 */

import {
  getHistory,
  getEntryById,
  addEntry,
  deleteEntry,
  clearHistory,
  getHistoryCount,
  exportToCsv,
  exportToJson,
} from "@/lib/storage/historyStore";
import { safeResponse, dangerousResponse } from "../fixtures";

/* ------------------------------------------------------------------ */
/*  Read operations                                                   */
/* ------------------------------------------------------------------ */

describe("getHistory", () => {
  it("returns an empty array when no history exists", () => {
    expect(getHistory()).toEqual([]);
  });

  it("returns entries after adding them", () => {
    addEntry("https://example.com", "url", safeResponse);
    const history = getHistory();
    expect(history).toHaveLength(1);
    expect(history[0].content).toBe("https://example.com");
  });

  it("returns newest first", () => {
    addEntry("first", "text", safeResponse);
    addEntry("second", "text", dangerousResponse);
    const history = getHistory();
    expect(history[0].content).toBe("second");
    expect(history[1].content).toBe("first");
  });
});

describe("getEntryById", () => {
  it("returns the entry when found", () => {
    const added = addEntry("https://example.com", "url", safeResponse);
    const found = getEntryById(added.id);
    expect(found).not.toBeNull();
    expect(found!.id).toBe(added.id);
  });

  it("returns null when not found", () => {
    expect(getEntryById("nonexistent-id")).toBeNull();
  });
});

/* ------------------------------------------------------------------ */
/*  Write operations                                                  */
/* ------------------------------------------------------------------ */

describe("addEntry", () => {
  it("generates a unique ID for each entry", () => {
    const a = addEntry("a", "text", safeResponse);
    const b = addEntry("b", "text", safeResponse);
    expect(a.id).not.toBe(b.id);
  });

  it("stores the correct content and contentType", () => {
    const entry = addEntry("https://phish.tk", "url", dangerousResponse);
    expect(entry.content).toBe("https://phish.tk");
    expect(entry.contentType).toBe("url");
  });

  it("extracts verdict data from the response", () => {
    const entry = addEntry("content", "text", dangerousResponse);
    expect(entry.threatLevel).toBe("dangerous");
    expect(entry.isPhishing).toBe(true);
    expect(entry.score).toBe(0.78);
  });

  it("persists to localStorage", () => {
    addEntry("test", "text", safeResponse);
    expect(localStorage.setItem).toHaveBeenCalled();
  });

  it("enforces FIFO eviction beyond max entries", () => {
    for (let i = 0; i < 105; i++) {
      addEntry(`url-${i}`, "url", safeResponse);
    }
    expect(getHistoryCount()).toBeLessThanOrEqual(100);
  });
});

describe("deleteEntry", () => {
  it("returns true and removes existing entry", () => {
    const entry = addEntry("test", "text", safeResponse);
    expect(deleteEntry(entry.id)).toBe(true);
    expect(getEntryById(entry.id)).toBeNull();
  });

  it("returns false for nonexistent ID", () => {
    expect(deleteEntry("no-such-id")).toBe(false);
  });

  it("does not affect other entries", () => {
    const a = addEntry("a", "text", safeResponse);
    const b = addEntry("b", "text", safeResponse);
    deleteEntry(a.id);
    expect(getEntryById(b.id)).not.toBeNull();
  });
});

describe("clearHistory", () => {
  it("removes all entries", () => {
    addEntry("a", "text", safeResponse);
    addEntry("b", "text", safeResponse);
    clearHistory();
    expect(getHistory()).toEqual([]);
  });

  it("calls localStorage.removeItem", () => {
    clearHistory();
    expect(localStorage.removeItem).toHaveBeenCalledWith("phishguard:history");
  });
});

/* ------------------------------------------------------------------ */
/*  Count                                                             */
/* ------------------------------------------------------------------ */

describe("getHistoryCount", () => {
  it("returns 0 for empty history", () => {
    expect(getHistoryCount()).toBe(0);
  });

  it("returns the correct count", () => {
    addEntry("a", "text", safeResponse);
    addEntry("b", "text", safeResponse);
    expect(getHistoryCount()).toBe(2);
  });
});

/* ------------------------------------------------------------------ */
/*  Export                                                             */
/* ------------------------------------------------------------------ */

describe("exportToJson", () => {
  it("does not throw when history is empty", () => {
    expect(() => exportToJson()).not.toThrow();
  });

  it("triggers a download via anchor element", () => {
    addEntry("test", "url", safeResponse);

    const appendSpy = jest.spyOn(document.body, "appendChild").mockImplementation(() => null as unknown as Node);
    const removeSpy = jest.spyOn(document.body, "removeChild").mockImplementation(() => null as unknown as Node);

    exportToJson();

    expect(appendSpy).toHaveBeenCalled();
    expect(removeSpy).toHaveBeenCalled();

    appendSpy.mockRestore();
    removeSpy.mockRestore();
  });
});

describe("exportToCsv", () => {
  it("does not throw when history is empty", () => {
    expect(() => exportToCsv()).not.toThrow();
  });

  it("triggers a download", () => {
    addEntry("test", "url", safeResponse);

    const appendSpy = jest.spyOn(document.body, "appendChild").mockImplementation(() => null as unknown as Node);
    const removeSpy = jest.spyOn(document.body, "removeChild").mockImplementation(() => null as unknown as Node);

    exportToCsv();

    expect(appendSpy).toHaveBeenCalled();

    appendSpy.mockRestore();
    removeSpy.mockRestore();
  });
});
