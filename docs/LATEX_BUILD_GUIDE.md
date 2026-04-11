# LaTeX Build Guide for PhishGuard Thesis

This document explains how the final LaTeX formatting was achieved using Visual Studio Code, starting from the original ELTE thesis template, resolving compilation issues, and fixing layout elements.

## 1. Initial Setup and Template Cloning
1. We started by downloading the official **ELTE FI thesis template** (`elteikthesis_en.tex` and `elteikthesis.cls`).
2. We used **Pandoc** to initially convert the monolithic `THESIS_COMPLETE_DOCUMENT.md` into individual LaTeX chapters.

## 2. Tools Installed
To compile the document locally on Ubuntu/Debian without Overleaf timeouts, the following tools were required:
*   **TeX Live (Full):** Installed via `sudo apt install texlive-full` to ensure all packages (like `biblatex`, `epstopdf`, `longtable`, `minted`) were available.
*   **Latexmk:** A Perl script that automates the generation of the PDF and handles multiple compilation passes for the table of contents and bibliography.
*   **VS Code + LaTeX Workshop Extension:** Provided an integrated development environment to compile and view the PDF in real-time, executing `latexmk -pdf` automatically on save.

## 3. Major Fixes and Modifications

### Resolving Compilation Timeouts (Longtables and Images)
*   **Tables:** The standard `tabular` environments inside `table` floats caused severe "overfull" and layout timeout errors because they exceeded page boundaries. We wrote Python scripts to convert every table into a `longtable` environment and clamped them to `0.85\textwidth`.
*   **Images:** Large images were forcing endless page-break recalculations. We globally applied a maximum constraint of `width=0.85\linewidth, height=0.65\textheight` to all `\includegraphics`. We also converted Mermaid diagrams to static PNGs and properly linked them.

### Removing Hardcoded Numbering
*   The original Markdown contained manual numbering (e.g., `1.1 Background`). When converted to LaTeX, this clashed with LaTeX's automatic `\chapter` and `\section` counters, producing messy results like `1.1.1 1.1 Background`.
*   We used a regex script (`sed`/`python`) to strip all hardcoded numbers from `\chapter{}`, `\section{}`, and `\subsection{}` commands across all `.tex` files.

### Fixing the "J. Discussion" Duplication Bug
*   The `elteikthesis_en.tex` main file mistakenly included all 10 chapters twice—once in the main body, and again at the very bottom of the file after the `\appendix` command. This caused the document to double in size (from 90 to 180 pages) and rendered the duplicated chapters as Appendices (e.g., "J. Discussion"). 
*   We deleted the duplicate `\include{}` statements at the end of the file.

### Formatting the Declaration of Authorship
*   The "Signature of the Author" block was originally placed at the bottom of Chapter 10, causing formatting issues.
*   In compliance with Dean's Instruction No. 1/2026, we extracted this into a separate, unnumbered chapter (`declaration.tex`), placing it directly after the title page. We used `minipage` blocks to professionally align the "Budapest, Hungary", "Date", and "Signature" fields side-by-side.

### Hiding Empty Lists
*   Because the Markdown converter did not generate explicit LaTeX `\caption{}` tags for tables or code blocks, the "List of Tables" and "List of Codes" rendered as blank pages.
*   We wrapped these optional lists in an `\iffalse ... \fi` block inside `elteikthesis_en.tex` to cleanly hide them from the final PDF.

## 4. Compilation Instructions
To rebuild the PDF from the `.tex` source files:
1. Open the `docs/latex_source` directory.
2. Run `latexmk -c` to clear old auxiliary files.
3. Run `latexmk -pdf elteikthesis_en.tex`.
4. The final output will be generated as `elteikthesis_en.pdf`.
