/**
 * Tests for lib/storage/historyStore.ts — localStorage-backed history CRUD.
 */

import {
  getHistory,
  getEntryById,
  addEntry,
  clearHistory,
  deleteEntry,
  getHistoryCount,
  exportToCsv,
  exportToJson,
  historyToCsv,
  getHistorySnapshot,
  subscribeHistory,
} from "@/lib/storage/historyStore";
import type { AnalysisResponse, HistoryEntry } from "@/types";
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



function makeResponse(score: number): AnalysisResponse {
  return {
    success: true,
    verdict: {
      isPhishing: score > 0.5,
      confidenceScore: score,
      threatLevel: score > 0.7 ? "critical" : "safe",
      reasons: [],
      recommendation: "",
    },
    osint: null,
    features: {
      urlFeatures: 0,
      textFeatures: 0,
      osintFeatures: 0,
      totalRiskIndicators: 0,
      detectedTactics: [],
    },
    explanation: null,
    analysisTime: 1,
    analyzedAt: new Date().toISOString(),
    error: null,
  };
}

/* ------------------------------------------------------------------ */
/*  Hardening (2026-08): quota safety, CSV injection, external store   */
/* ------------------------------------------------------------------ */

function makeEntry(content: string): HistoryEntry {
  const response = makeResponse(0.5);
  return {
    id: crypto.randomUUID(),
    content,
    contentType: "text",
    threatLevel: "suspicious",
    score: 0.5,
    isPhishing: false,
    analyzedAt: response.analyzedAt,
    response,
  };
}

describe("historyStore hardening", () => {
  beforeEach(() => {
    localStorage.clear();
    jest.restoreAllMocks();
  });

  afterEach(() => {
    localStorage.clear();
  });

  it("notifies subscribers on add", () => {
    const listener = jest.fn();
    const unsubscribe = subscribeHistory(listener);
    addEntry("https://example.com", "url", safeResponse);
    expect(listener).toHaveBeenCalledTimes(1);
    unsubscribe();
  });

  it("snapshot reference is stable between reads and changes on write", () => {
    clearHistory();
    const a = getHistorySnapshot();
    const b = getHistorySnapshot();
    expect(a).toBe(b); // stable identity — required by useSyncExternalStore

    addEntry("https://example.com", "url", safeResponse);
    expect(getHistorySnapshot()).not.toBe(a);
  });

  it("evicts oldest entries instead of throwing when quota is exceeded", () => {
    const setItem = jest.spyOn(Storage.prototype, "setItem");
    let calls = 0;
    setItem.mockImplementation(() => {
      calls += 1;
      if (calls > 1) {
        throw new DOMException("full", "QuotaExceededError");
      }
    });

    expect(() =>
      addEntry("https://big.com", "url", safeResponse),
    ).not.toThrow();
  });
});

describe("historyToCsv sanitization", () => {
  beforeEach(() => {
    localStorage.clear();
    jest.restoreAllMocks();
  });

  it("prefixes formula-triggering characters with a tab", () => {
    const csv = historyToCsv([
      makeEntry('=HYPERLINK("http://evil.com","click")'),
      makeEntry("+1+2"),
      makeEntry("-fragment"),
      makeEntry("@cmd"),
    ]);

    const dataLines = csv.split("\n").slice(1);
    // Quoted fields may contain commas, so assert on the raw cell text
    // rather than naively splitting on commas.
    expect(dataLines[0]).toContain('"\t=HYPERLINK');
    expect(dataLines[1]).toMatch(/^\d+,"\t\+1\+2",/);
    expect(dataLines[2]).toMatch(/^\d+,"\t-fragment",/);
    expect(dataLines[3]).toMatch(/^\d+,"\t@cmd",/);
  });

  it("escapes embedded quotes and commas safely", () => {
    const csv = historyToCsv([
      makeEntry('He said "hello", then left'),
    ]);
    expect(csv).toContain('"He said ""hello"", then left"');
  });

  it("leaves benign content untouched", () => {
    const csv = historyToCsv([makeEntry("https://example.com/page")]);
    expect(csv).toContain("https://example.com/page,");
  });
});
