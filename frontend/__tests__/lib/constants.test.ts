/**
 * Tests for lib/constants.ts — application-wide constants.
 */

import {
  DEFAULT_API_URL,
  API_BASE_URL,
  THREAT_LEVEL_MAP,
  SCORING_WEIGHTS,
  NAV_ITEMS,
  APP_NAME,
  APP_VERSION,
} from "@/lib/constants";

describe("API constants", () => {
  it("DEFAULT_API_URL is localhost:8000", () => {
    expect(DEFAULT_API_URL).toBe("http://localhost:8000");
  });

  it("API_BASE_URL is defined", () => {
    expect(API_BASE_URL).toBeDefined();
    expect(typeof API_BASE_URL).toBe("string");
  });
});

describe("THREAT_LEVEL_MAP", () => {
  const levels = ["safe", "suspicious", "dangerous", "critical"] as const;

  it("has all four threat levels", () => {
    for (const level of levels) {
      expect(THREAT_LEVEL_MAP[level]).toBeDefined();
    }
  });

  it.each(levels)("level '%s' has label, icon, and color classes", (level) => {
    const meta = THREAT_LEVEL_MAP[level];
    expect(meta.label).toBeTruthy();
    expect(meta.icon).toBeTruthy();
    expect(meta.colorClass).toBeTruthy();
    expect(meta.bgClass).toBeTruthy();
    expect(meta.borderClass).toBeTruthy();
  });

  it("safe label is 'Safe'", () => {
    expect(THREAT_LEVEL_MAP.safe.label).toBe("Safe");
  });

  it("critical label is 'Critical'", () => {
    expect(THREAT_LEVEL_MAP.critical.label).toBe("Critical");
  });
});

describe("SCORING_WEIGHTS", () => {
  it("contains text, url, and osint weights", () => {
    expect(SCORING_WEIGHTS.text).toBeDefined();
    expect(SCORING_WEIGHTS.url).toBeDefined();
    expect(SCORING_WEIGHTS.osint).toBeDefined();
  });

  it("weights sum to 1.0", () => {
    const sum = SCORING_WEIGHTS.text + SCORING_WEIGHTS.url + SCORING_WEIGHTS.osint;
    expect(sum).toBeCloseTo(1.0);
  });

  it("has correct individual weights", () => {
    expect(SCORING_WEIGHTS.text).toBe(0.4);
    expect(SCORING_WEIGHTS.url).toBe(0.25);
    expect(SCORING_WEIGHTS.osint).toBe(0.35);
  });
});

describe("NAV_ITEMS", () => {
  it("contains at least 5 navigation items", () => {
    expect(NAV_ITEMS.length).toBeGreaterThanOrEqual(5);
  });

  it("each item has title, href, and icon", () => {
    for (const item of NAV_ITEMS) {
      expect(item.title).toBeTruthy();
      expect(item.href).toBeTruthy();
      expect(item.icon).toBeTruthy();
    }
  });

  it("first item is Dashboard at /", () => {
    expect(NAV_ITEMS[0].title).toBe("Dashboard");
    expect(NAV_ITEMS[0].href).toBe("/");
  });

  it("includes Analyze and History routes", () => {
    const titles = NAV_ITEMS.map((item) => item.title);
    expect(titles).toContain("Analyze");
    expect(titles).toContain("History");
  });
});

describe("App metadata", () => {
  it("APP_NAME is PhishGuard", () => {
    expect(APP_NAME).toBe("PhishGuard");
  });

  it("APP_VERSION is a semver string", () => {
    expect(APP_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });
});
