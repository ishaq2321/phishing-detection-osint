/**
 * Root route — the product IS the analyser.
 *
 * Renders the Analyze page directly (no redirect hop, no meta-refresh
 * delay): the user lands on the paste-and-go screen instantly. The
 * activity dashboard lives at /dashboard.
 */
export { default } from "./analyze/page";
