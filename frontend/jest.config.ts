/**
 * Jest configuration for the PhishGuard frontend.
 *
 * Uses ts-jest to handle TypeScript and maps the `@/*` alias
 * to match the project's tsconfig paths.
 */

import type { Config } from "jest";

const config: Config = {
  testEnvironment: "jsdom",

  transform: {
    "^.+\\.tsx?$": [
      "ts-jest",
      {
        tsconfig: "tsconfig.json",
        /* Disable type-checking in tests for speed. */
        diagnostics: false,
      },
    ],
  },

  moduleNameMapper: {
    /* Mirror tsconfig `@/*` → `./src/*`. */
    "^@/(.*)$": "<rootDir>/src/$1",
  },

  /* ESM packages that need transpiling. */
  transformIgnorePatterns: [
    "node_modules/(?!(lucide-react|recharts|motion|@base-ui/react|sonner|next-themes)/)",
  ],

  setupFilesAfterEnv: ["<rootDir>/__tests__/setup.ts"],

  testMatch: ["**/__tests__/**/*.test.ts?(x)"],

  moduleFileExtensions: ["ts", "tsx", "js", "jsx", "json"],
};

export default config;
