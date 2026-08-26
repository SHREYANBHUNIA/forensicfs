# Analysis Service API

The Python service defined here is the trusted boundary between an analysis job and the native parser. It accepts only a signed evidence reference and case/job identifiers, downloads to ephemeral worker storage, verifies the SHA-256 digest, invokes the native process without a shell, and returns structured results.
