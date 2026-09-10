## Tools

1. GitHub Copilot
2. Google Gemini

## Prompts

1. [I gave context of the project] We need a database for JA3/JA3S/JA4/JA4S fingerprints. We have to decide where it lives, how it gets seeded, and how we keep it consistent across the Python and C++ engines.

2. We need more entries in ja3/ja3s/ja4/ja4s to expand our database, so the unknown issue comes less. Can you help me design a seed catalog and make sure it stays credible?

3. We are building the fingerprint database for both offline and live capture. Tell me how to structure the DB so that Redis is the runtime store and the repo still keeps a clean, versioned catalog.

4. Where will the Redis database exist? Is it local to my machine, or should it be part of the GitHub repo? What should be committed and what should stay runtime-only?

5. Is it ready to push on GitHub then? We need a database directory with seed data, but we do not want to commit runtime state from Redis.

6. We have to make the database. Are there files like seed_fingerprints.json and import_fingerprints.py? Explain how the workflow should look from seed file to Redis to final lookup.

7. We need to import more data from outside sources, but we must keep provenance and avoid duplicates. Can you help us write a loader that accepts JSON and CSV and preserves existing entries?

8. I want to expand the seed catalog with external JA4 mappings from FoxIO, but only for the TCP fingerprints relevant to this project. The import script should skip unsupported formats and avoid duplicates.

9. Can we add a database lookup cache and pipeline writes so repeated lookups are faster and the project remains efficient with Redis?

10. Can you help me review the DB logic to ensure it handles unknowns properly, preserves labels, and works in both Python and C++ without breaking the app?

11. The project needs the database to be deterministic and easy to validate. Tell me how to test the DB with known fingerprints and ensure that the Redis-backed records match the seed JSON.

12. We need the final repo to be clean and reproducible. Make sure the DB workflow works without manual Redis setup steps for every run, and document the expected behavior clearly.

13. We need to make a demo pcap file that correctly identifies at least 5 distinct clients/tools by fingerprint alone. Help me build a clean database-backed demo, not just a random capture.

14. Go through the JA3 and JA4 hashes present in our database and create at least 7 different pcap files with different clients and servers so the final demo is credible.

15. We have to keep the pcap demo clean. Please help me identify the actual client/server fingerprints we can trust from the DB and use only those in the final capture set.

16. We need a final validation of the demo. Tell me how to check that the PCAP identifies the known clients by fingerprint alone and that there are no unknown matches.

## Thought Process

The database work was designed around a very simple but important principle: the repo should keep a curated, versioned seed catalog, while Redis should be the runtime lookup layer that is used when the application is actively matching live or offline traffic. Instead of treating the database as just a bag of hashes, we treated it as a provenance-aware fingerprint catalog where each entry carries metadata about kind, role, source, version, and category.

AI was used as a technical pair programmer in the following way:

- designing the database architecture and deciding what belongs in GitHub versus runtime state
- shaping the JSON schema and record format for JA3, JA3S, JA4, and JA4S
- building the import pipeline from seed JSON and external CSV sources
- checking duplicate handling, provenance, and validation rules
- reviewing the lookup path and ensuring the project would not break when Redis was missing or stale
- helping validate the final demo database against real captured traffic

## Step-by-step details

1. We first clarified the requirement: the runtime database should be fast and queryable, but the repo must still keep a clean seed catalog that can be version-controlled and reviewed.

2. We discussed whether Redis should live inside the GitHub repository. The conclusion was that runtime state should not be committed, but the seed catalog, import scripts, and validation logic should be committed and reloaded when needed.

3. We analyzed the structure of the DB and decided that a typed record model was necessary, instead of a raw hash-to-label map. Each fingerprint needed at least:
   - kind (ja3, ja3s, ja4, ja4s)
   - hash value
   - role (client or server)
   - name or label
   - version, OS, category, source, and notes

4. We then moved to implementation. The project ended up with the following database files and responsibilities:
   - `code/db/seed_fingerprints.json` — the curated, project-owned seed catalog
   - `code/db/import_fingerprints.py` — imports JSON or CSV data into Redis while preserving metadata and rejecting malformed/duplicate entries
   - `code/db/seed_reference_db.py` — a supporting seeding script for older reference-style workflows
   - `code/python/src/db.py` — the runtime DB logic used by the Python side of the project

5. We also reviewed the practical issue that came up repeatedly: the database had too many unknowns because the seed catalog was incomplete. The response was to expand it with controlled, known local captures rather than guessing or adding unsupported labels.

6. We implemented import logic that both accepted JSON grouped by kind and accepted CSV rows with standard fingerprint metadata. This included validation for accepted hash formats and filtering for unsupported or duplicate entries.

7. We extended the import path to handle the FoxIO JA4 format, but only for relevant TCP fingerprints. Rejected rows were skipped so the database remained credible and did not get polluted by unsupported fields.

8. We then improved the runtime path with lookup caching and pipelining to reduce repeated Redis calls while keeping correctness intact.

9. We validated against the real local traffic produced by curl, OpenSSL, Python SSL, Python requests/urllib3, Chromium, and server-side captures. This was the final proof that the DB worked in practice rather than only in theory.

10. The final demo validation was especially important. After generating the clean master capture and checking it with the fingerprint engine, the result was:
    - 73 packets scanned
    - 9 ClientHellos found
    - 7 ServerHellos found
    - 0 unknown matches

This proved that the database logic and the seed catalog were aligned with the actual traffic we were trying to identify.

### AI tools used: GitHub Copilot + Google Gemini

### Primary prompts given

#### Database architecture and design

1. We need a database for JA3/JA3S/JA4/JA4S fingerprints. We have to decide where it lives, how it gets seeded, and how we keep it consistent across the Python and C++ engines.
2. We need more entries in ja3/ja3s/ja4/ja4s to expand our database, so the unknown issue comes less. Can you help me design a seed catalog and make sure it stays credible?
3. Where will the Redis database exist? Is it local to my machine, or should it be part of the GitHub repo? What should be committed and what should stay runtime-only?
4. Is it ready to push on GitHub then? We need a database directory with seed data, but we do not want to commit runtime state from Redis.

#### Seed and import workflow

5. We have to make the database. Are there files like seed_fingerprints.json and import_fingerprints.py? Explain how the workflow should look from seed file to Redis to final lookup.
6. We need to import more data from outside sources, but we must keep provenance and avoid duplicates. Can you help us write a loader that accepts JSON and CSV and preserves existing entries?
7. I want to expand the seed catalog with external JA4 mappings from FoxIO, but only for the TCP fingerprints relevant to this project. The import script should skip unsupported formats and avoid duplicates.
8. We need the import script to load JSON grouped by kind and CSV rows with standard fingerprint metadata, while preserving the project’s validation rules.

#### Runtime, capture validation, and final demo

9. Can we add a database lookup cache and pipeline writes so repeated lookups are faster and the project remains efficient with Redis?
10. Can you help me review the DB logic to ensure it handles unknowns properly, preserves labels, and works in both Python and C++ without breaking the app?
11. The project needs the database to be deterministic and easy to validate. Tell me how to test the DB with known fingerprints and ensure that the Redis-backed records match the seed JSON.
12. We need the final repo to be clean and reproducible. Make sure the DB workflow works without manual Redis setup steps for every run, and document the expected behavior clearly.
13. We need to make a demo pcap file that correctly identifies at least 5 distinct clients/tools by fingerprint alone. Help me build a clean database-backed demo, not just a random capture.
14. Go through the JA3 and JA4 hashes present in our database and create at least 7 different pcap files with different clients and servers so the final demo is credible.
15. We have to keep the pcap demo clean. Please help me identify the actual client/server fingerprints we can trust from the DB and use only those in the final capture set.
16. We need a final validation of the demo. Tell me how to check that the PCAP identifies the known clients by fingerprint alone and that there are no unknown matches.

## Files in scope while working on the DB

- `code/db/seed_fingerprints.json`
- `code/db/import_fingerprints.py`
- `code/db/seed_reference_db.py`
- `code/db/capture_manifest.json`
- `code/python/src/db.py`
- `code/reference/expected_hashes.csv`

## Summary of AI help received

AI support was used to:

- define the database architecture and runtime/seeding split
- decide the shape of the fingerprint record and metadata schema
- create a robust import workflow for curated JSON and external CSV catalogs
- validate and filter duplicates, malformed rows, and unsupported JA4 formats
- review the logic for unknown handling, label preservation, and deterministic matching
- improve runtime lookup efficiency through caching and pipelining
- support the final demo validation by checking the actual capture identities against the database

## Final outcome

The database layer ended up as a clean, versioned seed catalog backed by a runtime Redis lookup path. The seed data was expanded with locally observed and validated client/server fingerprints including curl, OpenSSL, Python ssl, Python requests/urllib3, Chromium, and server-side OpenSSL values. The final demo capture was then checked against the engine, and the result showed the database could correctly identify the capture families without unknown matches.

This was the final project state: a realistic, source-backed database that was validated against actual TLS traffic, and a clean demo PCAP that matched the database by fingerprint alone.
