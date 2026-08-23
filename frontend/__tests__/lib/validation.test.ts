/**
 * Unit Tests: Input Validation Helpers
 */

import {
  isValidHttpUrl,
  splitUrlLines,
  validateBatch,
} from "@/lib/validation";

describe("isValidHttpUrl", () => {
  it.each([
    "https://example.com",
    "http://example.com/login?a=1",
    "https://sub.domain.example.co.uk/path",
    "http://192.168.1.1/admin",
  ])("accepts %s", (url) => {
    expect(isValidHttpUrl(url)).toBe(true);
  });

  it.each([
    "",
    "   ",
    "not a url",
    "ftp://example.com",
    "javascript:alert(1)",
    "example.com",
    "https://",
    "https:// .com",
    `https://${"a".repeat(2100)}.com`,
    "https://exa mple.com",
  ])("rejects %s", (url) => {
    expect(isValidHttpUrl(url)).toBe(false);
  });
});

describe("splitUrlLines", () => {
  it("splits, trims, and drops empties", () => {
    expect(splitUrlLines(" a.com \n\nb.com\n\n")).toEqual(["a.com", "b.com"]);
  });

  it("returns empty array for blank input", () => {
    expect(splitUrlLines("  \n \n")).toEqual([]);
  });
});

describe("validateBatch", () => {
  it("partitions valid and invalid lines", () => {
    const { valid, invalid } = validateBatch(
      "https://good.com\nnot-a-url\nhttp://also.good.org/path",
    );
    expect(valid).toEqual(["https://good.com", "http://also.good.org/path"]);
    expect(invalid).toEqual(["not-a-url"]);
  });

  it("deduplicates valid entries while keeping all invalid ones", () => {
    const { valid, invalid } = validateBatch(
      "https://dupe.com\nhttps://dupe.com\nbad\nbad2",
    );
    expect(valid).toEqual(["https://dupe.com"]);
    expect(invalid).toEqual(["bad", "bad2"]);
  });
});
