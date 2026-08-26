import { describe, expect, it } from "vitest";
import { getForensicWorkspace } from "./forensicWorkspace";

describe("forensic workspace fixture", () => {
  it("contains derived forensic records but not raw evidence content", () => {
    const workspace = getForensicWorkspace();

    expect(workspace.evidence.objectKey).toMatch(/^evidence\//);
    expect(JSON.stringify(workspace)).not.toContain("evidenceBytes");
    expect(workspace.timeline).toEqual([...workspace.timeline].sort((left, right) => left.occurredAt.localeCompare(right.occurredAt)));
  });
});
