/**
 * Global test setup — runs before every test file.
 *
 * Imports @testing-library/jest-dom matchers (toBeInTheDocument, etc.)
 * and stubs out browser APIs not available in jsdom.
 */

import "@testing-library/jest-dom";

/* ------------------------------------------------------------------ */
/*  Stub localStorage                                                 */
/* ------------------------------------------------------------------ */

const localStorageMock = (() => {
  let store: Record<string, string> = {};

  return {
    getItem: jest.fn((key: string) => store[key] ?? null),
    setItem: jest.fn((key: string, value: string) => {
      store[key] = value;
    }),
    removeItem: jest.fn((key: string) => {
      delete store[key];
    }),
    clear: jest.fn(() => {
      store = {};
    }),
    get length() {
      return Object.keys(store).length;
    },
    key: jest.fn((index: number) => Object.keys(store)[index] ?? null),
  };
})();

Object.defineProperty(window, "localStorage", { value: localStorageMock });

/* ------------------------------------------------------------------ */
/*  Stub matchMedia                                                   */
/* ------------------------------------------------------------------ */

Object.defineProperty(window, "matchMedia", {
  writable: true,
  value: jest.fn().mockImplementation((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: jest.fn(),
    removeListener: jest.fn(),
    addEventListener: jest.fn(),
    removeEventListener: jest.fn(),
    dispatchEvent: jest.fn(),
  })),
});

/* ------------------------------------------------------------------ */
/*  Stub URL.createObjectURL / revokeObjectURL                        */
/* ------------------------------------------------------------------ */

if (typeof URL.createObjectURL === "undefined") {
  URL.createObjectURL = jest.fn(() => "blob:mock");
}
if (typeof URL.revokeObjectURL === "undefined") {
  URL.revokeObjectURL = jest.fn();
}

/* ------------------------------------------------------------------ */
/*  Reset mocks between tests                                         */
/* ------------------------------------------------------------------ */

beforeEach(() => {
  localStorage.clear();
  jest.clearAllMocks();
});
