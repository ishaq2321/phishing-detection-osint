/**
 * Tests for lib/storage/settingsStore.ts — localStorage-backed settings.
 */

import {
  getSettings,
  getSetting,
  updateSetting,
  resetSettings,
  DEFAULT_SETTINGS,
} from "@/lib/storage/settingsStore";

/* ------------------------------------------------------------------ */
/*  Read operations                                                   */
/* ------------------------------------------------------------------ */

describe("getSettings", () => {
  it("returns defaults when no settings are stored", () => {
    const settings = getSettings();
    expect(settings).toEqual(DEFAULT_SETTINGS);
  });

  it("returns stored settings merged with defaults", () => {
    localStorage.setItem(
      "phishguard:settings",
      JSON.stringify({ apiUrl: "http://custom:9000" }),
    );

    const settings = getSettings();
    expect(settings.apiUrl).toBe("http://custom:9000");
    expect(settings.resultsDetailLevel).toBe(DEFAULT_SETTINGS.resultsDetailLevel);
  });

  it("handles malformed JSON gracefully", () => {
    localStorage.setItem("phishguard:settings", "not-json");
    const settings = getSettings();
    expect(settings).toEqual(DEFAULT_SETTINGS);
  });
});

describe("getSetting", () => {
  it("returns the default value for a single key", () => {
    expect(getSetting("resultsDetailLevel")).toBe("detailed");
  });

  it("returns updated value after updateSetting", () => {
    updateSetting("maxHistoryEntries", 25);
    expect(getSetting("maxHistoryEntries")).toBe(25);
  });
});

/* ------------------------------------------------------------------ */
/*  Write operations                                                  */
/* ------------------------------------------------------------------ */

describe("updateSetting", () => {
  it("persists the updated value to localStorage", () => {
    updateSetting("apiUrl", "http://new-api:8080");
    expect(localStorage.setItem).toHaveBeenCalled();
    expect(getSetting("apiUrl")).toBe("http://new-api:8080");
  });

  it("returns the full updated settings object", () => {
    const updated = updateSetting("autoClearDays", 14);
    expect(updated.autoClearDays).toBe(14);
    expect(updated.apiUrl).toBe(DEFAULT_SETTINGS.apiUrl);
  });

  it("does not affect other settings", () => {
    updateSetting("resultsDetailLevel", "expert");
    expect(getSetting("maxHistoryEntries")).toBe(DEFAULT_SETTINGS.maxHistoryEntries);
  });
});

describe("resetSettings", () => {
  it("removes all stored settings", () => {
    updateSetting("apiUrl", "http://custom:9000");
    resetSettings();
    expect(localStorage.removeItem).toHaveBeenCalledWith("phishguard:settings");
  });

  it("returns the default settings", () => {
    updateSetting("apiUrl", "http://custom:9000");
    const result = resetSettings();
    expect(result).toEqual(DEFAULT_SETTINGS);
  });

  it("getSetting returns defaults after reset", () => {
    updateSetting("resultsDetailLevel", "expert");
    resetSettings();
    expect(getSetting("resultsDetailLevel")).toBe("detailed");
  });
});

/* ------------------------------------------------------------------ */
/*  DEFAULT_SETTINGS                                                  */
/* ------------------------------------------------------------------ */

describe("DEFAULT_SETTINGS", () => {
  it("has all expected keys", () => {
    expect(DEFAULT_SETTINGS).toHaveProperty("apiUrl");
    expect(DEFAULT_SETTINGS).toHaveProperty("resultsDetailLevel");
    expect(DEFAULT_SETTINGS).toHaveProperty("maxHistoryEntries");
    expect(DEFAULT_SETTINGS).toHaveProperty("autoClearDays");
  });

  it("has sensible default values", () => {
    expect(DEFAULT_SETTINGS.resultsDetailLevel).toBe("detailed");
    expect(DEFAULT_SETTINGS.maxHistoryEntries).toBe(50);
    expect(DEFAULT_SETTINGS.autoClearDays).toBe(0);
  });
});
