# Chapter 3: System Design and Architecture

## 3.1 Architectural Overview

The PhishGuard platform is engineered as a modern, decoupled, full-stack web application. The architectural design prioritizes low-latency inference, modular separation of concerns, and seamless user experience. To achieve these objectives, the system adopts a client-server architecture, cleanly separating the user interface and presentation logic from the heavy computational requirements of the machine learning and Open-Source Intelligence (OSINT) pipelines.

The overarching architecture is composed of two primary subsystems:
1.  **The Client-Side Application (Frontend):** A responsive, server-side rendered (SSR) web interface built with Next.js 16 and React 19. It is responsible for accepting user input, rendering complex analytical visualizations (e.g., SHAP waterfall charts), and managing client-side state.
2.  **The Analytical Engine (Backend):** A high-performance, asynchronous REST API constructed using the FastAPI framework in Python. It orchestrates the Natural Language Processing (NLP) pipeline, executes asynchronous network OSINT queries, performs feature engineering, and serves the XGBoost machine learning model.

This separation of concerns ensures that the computationally expensive operations—such as executing concurrent DNS queries and traversing gradient-boosted decision trees—do not block the main thread of the user interface, thereby guaranteeing a fluid and responsive user experience even under heavy analytical load.

---

## 3.2 High-Level Data Flow

The operational lifecycle of a threat analysis request within the PhishGuard architecture follows a deterministic, multi-stage pipeline. The data flow is designed to dynamically adapt based on the modality of the input (URL, email, or unstructured text).

**[FIGURE 3-1: High-Level System Data Flow]**
*How to create:*
1. Use a diagramming tool (e.g., draw.io or Lucidchart).
2. Create a sequence diagram illustrating the following flow:
   - **User Input:** The user submits text/URL via the Next.js Frontend.
   - **API Request:** The Frontend issues an HTTP POST request to the FastAPI `/api/analyze` endpoint.
   - **Router/Orchestrator:** The backend `orchestrator.py` receives the payload and determines the input modality.
   - **Parallel Processing:** For a URL, the Orchestrator concurrently triggers the `featureExtractor.py` (for lexical analysis) and the OSINT modules (`dnsChecker.py`, `whoisLookup.py`).
   - **Inference:** The extracted features are aggregated and passed to the XGBoost Model and SHAP Explainer.
   - **Response Generation:** The backend synthesizes a comprehensive JSON response containing the threat score, SHAP values, and OSINT findings.
   - **Visualization:** The Next.js Frontend parses the JSON and dynamically renders the results using Recharts and Tailwind CSS.
3. Export the diagram as a high-resolution PNG (300 DPI) and insert it here.

### 3.2.1 Input Modality Detection
Upon receiving a payload from the client, the backend orchestrator first subjects the input to a heuristic classification layer to determine its fundamental nature. The system utilizes rigorous regular expressions and parsing logic to classify the input as:
-   **URL:** A strictly formatted Uniform Resource Locator.
-   **Email:** A structured text block containing standard RFC 5322 email headers (e.g., "Subject:", "From:", "To:").
-   **Free Text:** Any unstructured text that fails to meet the strict criteria of a URL or email header.

This dynamic detection allows the user to paste any suspicious content into a single, unified input field without needing to manually specify the content type, significantly reducing user friction.

### 3.2.2 Routing and Pipeline Selection
Once the modality is determined, the orchestrator routes the payload to the appropriate analytical pipeline:
-   **URL Pipeline:** The payload is strictly analyzed using the XGBoost machine learning model. The system extracts 17 lexical structural features directly from the URL string. Simultaneously, the system dispatches asynchronous network requests to extract the 4 defining OSINT features (`hasValidMx`, `usesCdn`, `dnsRecordCount`, `hasValidDns`). These 21 dimensions are normalized and passed to the classifier.
-   **Text/Email Pipeline:** The payload bypasses the XGBoost model (which is strictly trained on URL feature vectors) and is instead routed to the `nlpAnalyzer.py` module. Here, a custom `spaCy` NLP pipeline evaluates the semantic structure of the text, extracting named entities, identifying urgent language patterns, and scoring the text based on established social engineering heuristics.

---

## 3.3 Backend Architecture: The Analytical Engine

The backend of PhishGuard is architected utilizing FastAPI, chosen specifically for its native support for asynchronous programming (`asyncio`) and its automated, strictly-typed data validation via Pydantic.

### 3.3.1 Asynchronous Concurrency Model
The integration of real-time OSINT constitutes the primary bottleneck in the analysis pipeline. Querying global DNS servers, establishing WHOIS connections, and communicating with third-party threat intelligence APIs introduce unavoidable network latency. 

To mitigate this, the FastAPI backend heavily leverages Python's `asyncio` ecosystem. The `dnsChecker.py` and `whoisLookup.py` modules do not execute sequentially. Instead, when a URL is submitted, the orchestrator spawns multiple concurrent asynchronous tasks. The event loop yields control during network I/O wait times, allowing the server to handle concurrent requests from multiple clients without thread-blocking. This architectural decision is critical in maintaining the system's strict latency budget of sub-3-second response times.

### 3.3.2 Pydantic Schema Validation
To guarantee structural integrity between the frontend and backend, PhishGuard utilizes Pydantic models to define strict data contracts. Every incoming request and outgoing response is automatically validated, serialized, and documented via OpenAPI.

For example, the core `AnalysisResponse` schema mathematically guarantees that the frontend will always receive a deterministic object containing the overall risk score, the classification category (Safe, Suspicious, or Phishing), the decomposed SHAP values, and the localized OSINT findings. This eliminates runtime parsing errors and provides a robust contract for frontend visualization.

### 3.3.3 Ephemeral History Store
Consistent with the project's scope as an academic prototype, PhishGuard eschews the complexity of a persistent relational database (e.g., PostgreSQL). Instead, the backend implements a highly efficient, thread-safe, in-memory `HistoryStore`.

The `historyStore.py` module utilizes a standard Python `collections.deque` structured as a First-In-First-Out (FIFO) queue with a hard limit of 100 entries. When a user submits an analysis, the backend generates a unique UUID, stores the full `AnalysisResponse` object in the deque, and assigns a timestamp. Because FastAPI operates on a single primary event loop, concurrent asynchronous mutations to this deque are fundamentally thread-safe without requiring complex locking mechanisms. This design allows users to review their recent analysis history instantly without the latency or configuration overhead of a persistent database connection.

---

## 3.4 Frontend Architecture: The Presentation Layer

The frontend is constructed using Next.js 16 (App Router) and React 19, focusing heavily on performance, modern UI/UX paradigms, and complex data visualization.

### 3.4.1 Component-Based Structure
The user interface is strictly modular, adhering to React's component-based philosophy. The architecture leverages the `shadcn/ui` component library alongside `@base-ui/react` to provide accessible, highly customizable foundational components (e.g., buttons, input fields, modals). 

The application logic is separated into logical directories:
-   `src/app`: Contains the routing logic, global layouts, and top-level page components for the analyzer and history views.
-   `src/components`: Houses reusable UI elements. Complex visual representations, such as the SHAP value waterfall charts, are isolated into highly specific visualization components utilizing the `recharts` library.

### 3.4.2 State Management and Data Fetching
State management within the application is handled primarily through React's native hooks (`useState`, `useEffect`, `useContext`). The application consciously avoids heavyweight global state managers (like Redux or Zustand) in favor of localized, prop-drilled state where appropriate, aligning with the modern Next.js Server Components paradigm. 

Communication with the FastAPI backend is achieved via native `fetch` requests, wrapped in robust error-handling logic. The application utilizes the `sonner` library to provide non-blocking, toast-based notification feedback to the user regarding the success or failure of network requests or analysis operations.

### 3.4.3 Visual Presentation and Theming
A critical requirement of the system was the delivery of a professional, "dark-mode" optimized aesthetic typical of modern cybersecurity tools. The application achieves this via `tailwindcss` (version 4) for utility-first styling and `next-themes` for seamless theme switching. The visual hierarchy utilizes distinct color coding to rapidly communicate threat levels: green for 'Safe', amber for 'Suspicious', and red for critical 'Phishing' indicators. Fluid animations and transitions, powered by the `motion` (Framer Motion) library, are employed to provide immediate visual feedback during the analysis lifecycle, bridging the perceived latency gap during network OSINT queries.

---

## 3.5 Summary

This chapter detailed the structural engineering of the PhishGuard platform. The architecture successfully isolates the Next.js presentation layer from the FastAPI analytical engine. By employing an asynchronous concurrency model in Python and an in-memory deque for history management, the system achieves the necessary performance metrics required for real-time threat analysis without unnecessary database bloat. 

The subsequent chapter, Chapter 4, will delve deeply into the mathematical core of this architecture: the feature engineering pipeline, the XGBoost classification model, and the Optuna optimization strategy.

---

**End of Chapter 3**