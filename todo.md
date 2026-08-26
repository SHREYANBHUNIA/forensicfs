# Project TODO

- [x] Define the deploy-safe boundary between the React dashboard, TypeScript application server, Python FastAPI analysis service, and C++ filesystem engine.
- [x] Create the requested repository areas: image-parser, filesystem, metadata, recovery, timeline, signatures, analysis, api, dashboard, and tests.
- [x] Add the C++ filesystem-analysis executable scaffold with structured findings output and unit coverage.
- [x] Add the Python FastAPI analysis-service boundary that validates disk-image jobs and invokes the C++ engine with least-privilege assumptions.
- [x] Implement case, image-reference, file-record, finding, and timeline persistence models without storing disk-image bytes in database rows.
- [x] Implement secure disk-image intake that stores only an external object reference and integrity metadata in case records.
- [x] Implement APIs for case navigation, analysis status, searchable file records, findings, directory trees, and case-wide timelines.
- [x] Build a React forensic dashboard with a high-contrast white typographic visual system, offset grayscale display title, and restrained red forensic accents.
- [x] Add foundational automated tests for the analysis contracts and forensic record transformations.
- [x] Run type checks and automated tests, validate the dashboard visually, and create a delivery checkpoint.
