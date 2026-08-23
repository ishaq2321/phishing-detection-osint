/**
 * Public API of the `lib/api` module.
 *
 * Import everything from `@/lib/api` instead of reaching into
 * individual files.
 *
 * @example
 * ```ts
 * import { analyzeUrl, checkHealthLive, NetworkError, friendlyErrorMessage } from "@/lib/api";
 * ```
 */

/* Endpoint functions */
export {
  analyzeContent,
  analyzeUrl,
  analyzeEmail,
  checkHealthLive,
  pingApi,
  getModelStatus,
} from "./endpoints";

/* Low-level client (rarely needed directly) */
export { apiClient, type RequestOptions } from "./client";

/* Error classes & helpers */
export {
  NetworkError,
  ApiError,
  ValidationError,
  friendlyErrorMessage,
  type ValidationDetail,
} from "./errors";
