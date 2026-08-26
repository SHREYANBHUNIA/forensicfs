# Dashboard Disk-Image Intake Contract

ForensicFS accepts an evidence image through an **authenticated, browser-to-object-storage transfer**. The application server creates a user-scoped object key and asks the storage service for a signed single-use upload URL. The browser uploads the file directly to that URL; it does not pass evidence bytes through the dashboard server or any database record.

| Contract element | Rule |
|---|---|
| Eligibility | A signed-in investigator is required before an upload URL can be issued. |
| Accepted image names | `.img`, `.dd`, `.raw`, `.e01`, `.vhd`, `.vhdx`, and `.qcow2` are accepted as an intake allow-list. |
| Client-side limit | Direct intake is limited to 512 MiB per file in the dashboard flow. Larger or multipart evidence requires the isolated worker intake path. |
| Object namespace | Keys are generated as `evidence/{userId}/{caseId}/{safeFilename}`. The client cannot choose a storage namespace. |
| Evidence persistence | Only the generated key, filename, declared size, media type, and eventual worker-derived SHA-256 digest are persisted. Disk-image bytes never enter SQLite rows. |
| Processing handoff | Completion creates a typed case handoff request for the included no-cost self-hosted FastAPI worker, which must verify its own streamed SHA-256 digest before native parsing. |

## Timeline Filters

The timeline supports independent event-type toggles for **creation**, **modification**, **access**, **metadata change**, and **deletion**. The event filter is a presentation control only: it neither changes the underlying chronology nor omits events from the retained case result.
