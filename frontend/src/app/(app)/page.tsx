import { redirect } from "next/navigation";

/**
 * Root route — the product IS the analyzer.
 *
 * Users land directly on the paste-and-analyse screen; the activity
 * dashboard moved to /dashboard for those who want it.
 */
export default function Home() {
  redirect("/analyze");
}
