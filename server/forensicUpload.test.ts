import { describe, expect, it } from "vitest";
import { MAX_EVIDENCE_BYTES, validateEvidenceIntake } from "./forensicUpload";

describe("evidence intake validation", () => {
  it("sanitizes a supported disk-image filename without retaining a client path", () => {
    expect(validateEvidenceIntake({ fileName: "../evidence/Case 01.RAW", sizeBytes: 128, mediaType: "" })).toEqual({
      fileName: "_evidence_Case_01.RAW",
      sizeBytes: 128,
      mediaType: "application/octet-stream",
    });
  });

  it("rejects unsupported files and oversized intake requests", () => {
    expect(() => validateEvidenceIntake({ fileName: "notes.pdf", sizeBytes: 128, mediaType: "application/pdf" })).toThrow("supported disk image");
    expect(() => validateEvidenceIntake({ fileName: "disk.img", sizeBytes: MAX_EVIDENCE_BYTES + 1, mediaType: "application/octet-stream" })).toThrow("512 MiB");
  });
});
