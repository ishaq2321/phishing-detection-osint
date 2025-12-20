# Copilot Instructions for Thesis Project

## Project Overview
This is a BSc thesis project for the Faculty of Informatics at Eötvös Loránd University (ELTE). The thesis must culminate in a **fully functional product with a user interface (UI)** to facilitate user interaction.

📄 **Thesis Registration Document:** [Ishaq Muhammad (PXPRGK); Request identifier-1654818362; Request submission date-1092025 112213 AM.pdf](../Ishaq%20Muhammad%20%28PXPRGK%29%3B%20Request%20identifier-1654818362%3B%20Request%20submission%20date-1092025%20112213%20AM.pdf)

> Always refer to the PDF file above for the official thesis topic, scope, and requirements.

---

## Deadlines & Milestones

| Milestone | Deadline | Key Deliverables |
|-----------|----------|------------------|
| **Milestone 1** | December 20, 2025 | Finalize topic & plan, background research, system design diagrams, GitLab setup, initial prototype |
| **Milestone 2** | February 20, 2026 | Core algorithm/model implementation, backend integration, dataset collection & preprocessing, preliminary tests |
| **Milestone 3** | March 25, 2026 | UI development & integration, performance improvements, solid test coverage, methodology & results draft |
| **Milestone 4** | April 15, 2026 | Final implementation, complete documentation, user guide, developer docs, full thesis draft |
| **Final Submission** | May 1, 2026 | Official thesis submission (only minor corrections after April 15) |

---

## Naming Conventions

- **Primary Convention:** `camelCase` for all code (variables, functions, methods, classes)
- **Database Exception:** Use `snake_case` for database table names, column names, and SQL-related identifiers
- **Files:** Use `camelCase` for source files (e.g., `userController.js`, `dataProcessor.py`)
- **Constants:** Use `UPPER_SNAKE_CASE` for constants (e.g., `MAX_RETRY_COUNT`)

### Examples
```
// Code
const userName = "Ishaq";
function processUserData() {}

// Database
CREATE TABLE user_profiles (user_id INT, created_at TIMESTAMP);
```

---

## Code Quality Rules

### Clean Code Principles
- Write self-documenting code with meaningful names
- Keep functions small and focused (single responsibility)
- Use comments only when necessary to explain "why", not "what"
- Follow DRY (Don't Repeat Yourself) principle

### Forbidden Practices
- ❌ **No dead code** – Remove unused functions, variables, and imports
- ❌ **No empty files** – Every file must have a purpose
- ❌ **No conflicting duplicates** – Avoid duplicate logic; refactor into reusable components
- ❌ **No unnecessary code** – Remove console.logs, debug statements, and commented-out code before commits
- ❌ **No hardcoded values** – Use configuration files or environment variables

### Required Practices
- ✅ Consistent indentation and formatting
- ✅ Proper error handling with meaningful messages
- ✅ Input validation for all user inputs
- ✅ Modular architecture with clear separation of concerns
- ✅ Comprehensive documentation for all components

---

## Project Requirements

### Must-Have Features
1. **Functional User Interface** – Intuitive, user-friendly, and accessible
2. **Backend Integration** – Proper API design and data flow
3. **Core Algorithm/Model** – Main thesis implementation
4. **Testing** – Unit tests, integration tests, and solid coverage
5. **Documentation** – Architecture docs, user guide, developer guide

### Documentation Checklist
- [ ] System architecture diagrams
- [ ] API documentation
- [ ] User guide with screenshots
- [ ] Developer setup instructions
- [ ] Testing documentation
- [ ] Thesis report (methodology, results, evaluation)

---

## Supervisor Information
- **Supervisor:** Arafat
- **Communication:** Microsoft Teams (chat or meetings)
- **Meeting Requests:** At least 2 days in advance
- **Progress Reports:** Submit code, test results, closed issues, and progress summary for each milestone

---

## GitLab Repository Guidelines
- Define milestones matching the deadlines above
- Use issues to track tasks and progress
- Close issues with meaningful commit messages
- Maintain clean commit history

---

## Quick Reference for Copilot

When assisting with this thesis:
1. Always check the PDF for project scope and requirements
2. Follow `camelCase` for code, `snake_case` for database
3. Enforce clean code rules – no dead code, duplicates, or empty files
4. Ensure all features have proper UI components
5. Include proper error handling and validation
6. Write testable, modular code
7. Keep documentation up to date

---

*Emily, let's make this thesis journey smooth and successful! 🎓*
