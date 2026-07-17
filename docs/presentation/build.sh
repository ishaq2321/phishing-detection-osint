#!/bin/bash
# Build the PhishGuard defense presentation PDF
# Usage: ./build.sh

set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

echo "==> Compiling presentation.tex..."
pdflatex -interaction=nonstopmode presentation.tex
pdflatex -interaction=nonstopmode presentation.tex  # second pass for TOC/bookmarks
echo ""
echo "==> Done: presentation.pdf ($(du -h presentation.pdf | cut -f1))"
echo "    Pages: $(pdfinfo presentation.pdf 2>/dev/null | grep Pages | awk '{print $2}' || echo '?')"
