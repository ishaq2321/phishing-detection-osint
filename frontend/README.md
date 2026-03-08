# PhishGuard Frontend

Next.js 16 web application for the PhishGuard phishing detection system.

## Tech Stack

| Technology          | Version | Purpose                             |
|---------------------|---------|-------------------------------------|
| Next.js (App Router)| 16.1.6  | React framework, file-based routing |
| React               | 19.2.3  | UI library                          |
| TypeScript          | 5.x     | Type safety                         |
| Tailwind CSS        | v4      | Utility-first styling               |
| shadcn/ui           | v4      | Accessible component library        |
| @base-ui/react      | latest  | Headless primitives (used by shadcn) |
| Recharts            | 3.8     | Score visualisation charts           |
| TanStack Table      | 8.21    | Data table with sorting/filtering   |
| Motion              | v12+    | Page transitions and animations     |
| next-themes         | latest  | Dark/light/system theme             |
| sonner              | latest  | Toast notifications                 |

## Prerequisites

- **Node.js** ≥ 20 (`node --version`)
- **npm** ≥ 10 (`npm --version`)
- Backend running on `http://localhost:8000` (see root README)

## Setup

```bash
# Install dependencies
npm install

# (Optional) Configure environment
cp .env.example .env.local

# Start development server
npm run dev
```

Open **http://localhost:3000** in your browser.

## Scripts

| Command            | Description                                     |
|--------------------|-------------------------------------------------|
| `npm run dev`      | Start development server (Turbopack, port 3000) |
| `npm run build`    | Production build                                |
| `npm run start`    | Serve production build                          |
| `npm run lint`     | Run ESLint                                      |
| `npm test`         | Run Jest unit tests                             |
| `npm run test:e2e` | Run Playwright E2E tests                        |
| `npm run test:e2e:ui` | Playwright E2E tests in interactive UI mode  |

## Project Structure

```
src/
├── app/                    # Next.js App Router
│   ├── (app)/              # Route group with shared layout
│   │   ├── page.tsx        # Dashboard (/)
│   │   ├── analyze/
│   │   │   ├── page.tsx    # Analyse form (/analyze)
│   │   │   └── batch/
│   │   │       └── page.tsx # Batch analysis (/analyze/batch)
│   │   ├── results/
│   │   │   └── page.tsx    # Results display (/results)
│   │   ├── history/
│   │   │   └── page.tsx    # History table (/history)
│   │   ├── how-it-works/
│   │   │   └── page.tsx    # Methodology (/how-it-works)
│   │   ├── settings/
│   │   │   └── page.tsx    # Settings (/settings)
│   │   └── layout.tsx      # App shell (sidebar + header)
│   ├── layout.tsx          # Root layout (providers, metadata)
│   └── globals.css         # Tailwind base styles
├── components/
│   ├── analyze/            # Analysis form components
│   ├── brand/              # Logo and branding
│   ├── charts/             # Score visualisations (Recharts)
│   ├── history/            # History table
│   ├── layout/             # Sidebar, header, footer
│   ├── methodology/        # Pipeline diagram
│   ├── results/            # Verdict, OSINT, feature cards
│   ├── shortcuts/          # Keyboard shortcuts dialog
│   └── ui/                 # shadcn/ui base components
├── hooks/                  # Custom React hooks
├── lib/
│   ├── api/                # API client and endpoints
│   ├── storage/            # localStorage stores
│   ├── constants.ts        # App constants
│   ├── resultsContext.tsx   # Cross-page result context
│   ├── toast.ts            # Toast notification helpers
│   └── utils.ts            # Utility functions
└── types/                  # TypeScript type definitions

e2e/                        # Playwright E2E tests (11 spec files)
__tests__/                  # Jest unit tests (10 test files)
public/                     # Static assets (logo, favicon, PWA)
```

## Routes

| Route             | Page              | Description                     |
|-------------------|-------------------|---------------------------------|
| `/`               | Dashboard         | Welcome, capabilities, CTA      |
| `/analyze`        | Analyse           | URL/email/text input form       |
| `/analyze/batch`  | Batch Analysis    | Multi-URL parallel analysis     |
| `/results`        | Results           | Verdict, scores, visualisations |
| `/history`        | History           | Past analyses table             |
| `/how-it-works`   | How It Works      | Methodology documentation       |
| `/settings`       | Settings          | API config, preferences         |

## Keyboard Shortcuts

| Shortcut        | Action               |
|-----------------|-----------------------|
| `/`             | Focus search input    |
| `Ctrl+Enter`   | Submit analysis       |
| `Ctrl+Shift+D` | Toggle dark mode      |
| `Ctrl+H`       | Go to history         |
| `Ctrl+N`       | New analysis          |
| `?`             | Show shortcuts help   |
| `Escape`        | Close dialog          |

## Testing

### Unit Tests (128 tests)

```bash
npm test                    # Run all
npm test -- --watch         # Watch mode
npm test -- --coverage      # With coverage report
```

### E2E Tests (28 tests)

```bash
# First time: install browsers
npx playwright install chromium

# Run tests
npm run test:e2e

# Interactive UI mode
npm run test:e2e:ui

# Run specific test file
npx playwright test e2e/urlAnalysis.spec.ts
```

## Environment Variables

| Variable                  | Default                  | Description              |
|---------------------------|--------------------------|--------------------------|
| `NEXT_PUBLIC_API_URL`     | `http://localhost:8000`  | Backend API base URL     |
| `NEXT_PUBLIC_APP_NAME`    | `PhishGuard`             | Application name         |

See [.env.example](.env.example) for all variables.

## Conventions

- **camelCase** for all code (variables, functions, components, files)
- **snake_case** for database/API fields from backend
- Components in PascalCase directories matching component name
- Barrel exports via `index.ts` files
- shadcn/ui v4 uses `@base-ui/react` — use `render` prop (not `asChild`)
- Import animations from `motion/react` (not `framer-motion`)
