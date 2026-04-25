# Thesis Documentation Updates — Pending

Track all codebase changes that require thesis documentation updates.
Check off each item once the thesis is updated.

## Settings Wiring (Frontend — DONE in code)

- [ ] Ch2 (User Documentation): Update Settings section — all 4 settings now actually work
  - apiUrl: changing it now routes ALL API calls to the new backend (not just Test Connection)
  - resultsDetailLevel: Simple/Detailed/Expert now controls which sections render on Results page
  - maxHistoryEntries: History store now respects the configured limit (was hardcoded to 100)
  - autoClearDays: Entries older than the configured period are now automatically purged
- [ ] Ch2: Results page description — mention detail-level conditional rendering (Simple vs Detailed vs Expert)
- [ ] Ch2: History page description — mention auto-clear and configurable max entries
- [ ] Ch4 (Methodology): If architecture diagram mentions hardcoded MAX_ENTRIES=100, update to "configurable via settings"
- [ ] Ch3 (Developer Documentation): settingsStore → historyStore dependency now exists (circular import risk note)

## Backend Stubs & Dead Code (ALL DONE in code)

- [x] Internal blocklist stub — now returns `no_data` (confidence=0.0) instead of misleading `clean`
- [x] PhishTank / Google Safe Browsing enum values removed from ReputationSource and DataSource
- [x] 6 dead config settings removed (httpTimeout, apiRateLimit, apiPrefix, cacheEnabled, cacheTtlSeconds, googleSafeBrowsingApiKey)
- [x] Threshold system unified — all 4 systems now use safe<0.3 / suspicious<0.5 / dangerous<0.7 / critical>=0.7
- [x] analyzerEngine='llm' dead path removed — AnalyzerEngine enum now only has NLP
- [x] 4 unused PhishingTactic enum values now implemented (EMOTIONAL_MANIPULATION, MONETARY_REQUEST, ATTACHMENT_MALWARE, SOCIAL_PROOF)
- [x] Brand name lists unified — both urlAnalyzer and nlpAnalyzer now cover all 17 brands (10 URL + 7 financial/shipping)
- [ ] Internal blocklist — update Ch3/Ch4 to document that it now returns no_data instead of clean
- [ ] PhishTank/GoogleSafeBrowsing — update class diagram to remove these enum values
- [ ] 6 dead config settings — remove from Ch3 config documentation and .env.example references
- [ ] Threshold unification — update ALL threshold references in Ch4 and Ch5 to unified system:
  - SAFE < 0.3, SUSPICIOUS < 0.5, DANGEROUS < 0.7, CRITICAL >= 0.7
  - PHISHING_THRESHOLD = 0.5 (was 0.6 in NLP, 0.5 in orchestrator/predictor, now unified to 0.5)
  - RiskLevel enum changed from 5-level (SAFE/LOW/MEDIUM/HIGH/CRITICAL) to 4-level (SAFE/SUSPICIOUS/DANGEROUS/CRITICAL)
  - NLP determineThreatLevel() now uses same thresholds as orchestrator
  - Scorer's isPhishing() threshold changed from 0.6 to 0.5
- [ ] AnalyzerEngine — remove LLM from Ch3 config docs
- [ ] PhishingTactic — add 4 newly implemented tactics to feature dictionary in Ch4
- [ ] Brand detection — update Ch4 to document all 17 brands in both URL and NLP analyzers

## Diagram Updates

- [ ] class-diagram.mmd: Remove PHISHTANK and GOOGLE_SAFE_BROWSING from ReputationSource enum
- [ ] class-diagram.mmd: Remove SSL and HTTP_HEADERS from DataSource enum
- [ ] class-diagram.mmd: Add EMOTIONAL_MANIPULATION, MONETARY_REQUEST, ATTACHMENT_MALWARE, SOCIAL_PROOF to PhishingTactic enum
- [ ] class-diagram.mmd: Update RiskLevel enum from 5-level to 4-level (remove LOW/MEDIUM/HIGH, add SUSPICIOUS/DANGEROUS)
- [ ] class-diagram.mmd: Remove LLM from AnalyzerEngine enum
- [ ] class-diagram.mmd: Update Settings class — remove 6 dead settings, remove googleSafeBrowsingApiKey
- [ ] system-architecture.mmd: Update threshold labels to unified 0.3/0.5/0.7 system
- [ ] sequence-diagram.mmd: If auto-clear logic added to history flow, consider adding a step

## Cross-Chapter Consistency

- [ ] Verify all threshold numbers match the unified system (Ch4 + Ch5)
- [ ] Verify RiskLevel enum is 4-level everywhere (no LOW/MEDIUM/HIGH references)
- [ ] Verify PHISHING_THRESHOLD is 0.5 everywhere (no 0.6 references)
- [ ] Verify feature counts still accurate (21 model features)
- [ ] Verify test count: 725 total (592 backend + 133 frontend)
- [ ] Verify PhishingTactic count is now 10 (was 6)
- [ ] Verify brand count is 17 in both analyzers
- [ ] Remove any references to PhishTank or Google Safe Browsing as operational sources
- [ ] Remove any references to LLM analyzer engine
- [ ] Re-compile PDF and verify page count