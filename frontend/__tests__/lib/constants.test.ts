/**
 * Tests for lib/constants.ts — application-wide constants.
 */

import {
  DEFAULT_API_URL,
  API_BASE_URL,
  THREAT_LEVEL_MAP,
  URL_SCORING_WEIGHTS,
  TEXT_SCORING_WEIGHTS,
  MODEL_METRICS,
  NAV_ITEMS,
  APP_NAME,
  APP_VERSION,
} from "@/lib/constants";

describe("API constants", () => {
  it("DEFAULT_API_URL falls back to a sensible default when env unset", () => {
    expect(DEFAULT_API_URL).toBeDefined();
    expect(typeof DEFAULT_API_URL).toBe("string");
    // When the production env var is unset, fallback is a stable URL.
    expect(DEFAULT_API_URL).toMatch(/^https?:\/\//);
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

describe("URL_SCORING_WEIGHTS", () => {
  it("contains ml and text weights", () => {
    expect(URL_SCORING_WEIGHTS.ml).toBeDefined();
    expect(URL_SCORING_WEIGHTS.text).toBeDefined();
  });

  it("weights sum to 1.0", () => {
    const sum = URL_SCORING_WEIGHTS.ml + URL_SCORING_WEIGHTS.text;
    expect(sum).toBeCloseTo(1.0);
  });

  it("has correct individual weights", () => {
    expect(URL_SCORING_WEIGHTS.ml).toBe(0.85);
    expect(URL_SCORING_WEIGHTS.text).toBe(0.15);
  });
});

describe("TEXT_SCORING_WEIGHTS", () => {
  it("contains text, url, and osint weights", () => {
    expect(TEXT_SCORING_WEIGHTS.text).toBeDefined();
    expect(TEXT_SCORING_WEIGHTS.url).toBeDefined();
    expect(TEXT_SCORING_WEIGHTS.osint).toBeDefined();
  });

  it("weights sum to 1.0", () => {
    const sum = TEXT_SCORING_WEIGHTS.text + TEXT_SCORING_WEIGHTS.url + TEXT_SCORING_WEIGHTS.osint;
    expect(sum).toBeCloseTo(1.0);
  });
});

describe("MODEL_METRICS", () => {
  it("has accuracy above 0.9", () => {
    expect(MODEL_METRICS.accuracy).toBeGreaterThan(0.9);
  });

  it("has featureCount of 21", () => {
    expect(MODEL_METRICS.featureCount).toBe(21);
  });

  it("has training and test sample counts", () => {
    expect(MODEL_METRICS.trainSamples).toBeGreaterThan(0);
    expect(MODEL_METRICS.testSamples).toBeGreaterThan(0);
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
