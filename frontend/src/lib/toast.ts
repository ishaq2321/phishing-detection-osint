/**
 * Toast helper functions — thin wrappers around Sonner's `toast` API
 * for consistent notification behaviour across the app.
 *
 * Usage:
 *   import { showSuccess, showError } from "@/lib/toast";
 *   showSuccess("Analysis complete!");
 *   showError("Backend unreachable", "Check your connection.");
 */

import { toast } from "sonner";

/** Show a success toast (green). */
export function showSuccess(message: string, description?: string) {
  toast.success(message, { description });
}

/** Show an error toast (red). */
export function showError(message: string, description?: string) {
  toast.error(message, { description });
}

/** Show a warning toast (yellow/amber). */
export function showWarning(message: string, description?: string) {
  toast.warning(message, { description });
}

/** Show an informational toast (blue). */
export function showInfo(message: string, description?: string) {
  toast.info(message, { description });
}

/** Show a loading toast that resolves to success or error. */
export function showPromise<T>(
  promise: Promise<T>,
  messages: {
    loading: string;
    success: string;
    error: string;
  },
) {
  return toast.promise(promise, messages);
}
