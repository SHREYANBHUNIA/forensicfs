import type { ForensicCaseWorkspace } from "../shared/forensics";

/**
 * Contract fixture used by the web workspace before an isolated FastAPI worker
 * is connected. It contains derived record metadata only—never evidence bytes.
 */
const workspaceFixture: ForensicCaseWorkspace = {
  caseId: "case_20260820_6de4a8c1",
  displayName: "CASE / 02794",
  status: "complete",
  filesystemType: "ext4",
  evidence: {
    originalName: "workspace-volume.img",
    sha256: "8ecab0b6b0fea48933e1674839e2624c2517beb4ab1dcf9c66b8a2d193fca25c",
    sizeBytes: 8589934592,
    objectKey: "evidence/case_20260820_6de4a8c1/workspace-volume.img",
  },
  files: [
    {
      recordId: "file-001",
      path: "/home/analyst/Notes/launch_plan.pdf",
      name: "launch_plan.pdf",
      parentPath: "/home/analyst/Notes",
      entryType: "file",
      extension: "pdf",
      sizeBytes: 298124,
      inode: "590821",
      allocationState: "allocated",
      macTimes: { createdAt: "2026-08-20T10:31:14Z", modifiedAt: "2026-08-20T10:45:08Z", accessedAt: "2026-08-20T10:46:17Z", changedAt: "2026-08-20T10:45:08Z" },
      signature: "PDF document",
      signatureMatchesExtension: true,
    },
    {
      recordId: "file-002",
      path: "/home/analyst/.cache/update.jpg",
      name: "update.jpg",
      parentPath: "/home/analyst/.cache",
      entryType: "file",
      extension: "jpg",
      sizeBytes: 241664,
      inode: "590998",
      allocationState: "allocated",
      macTimes: { createdAt: "2026-08-20T10:42:31Z", modifiedAt: "2026-08-20T10:43:08Z", accessedAt: "2026-08-20T10:43:08Z", changedAt: "2026-08-20T10:43:08Z" },
      signature: "PE executable",
      signatureMatchesExtension: false,
    },
    {
      recordId: "file-003",
      path: "/home/analyst/Downloads/remote_tool.exe",
      name: "remote_tool.exe",
      parentPath: "/home/analyst/Downloads",
      entryType: "file",
      extension: "exe",
      sizeBytes: 1840128,
      inode: "591204",
      allocationState: "deleted",
      macTimes: { createdAt: "2026-08-20T10:49:27Z", modifiedAt: "2026-08-20T10:54:59Z", accessedAt: "2026-08-20T10:55:03Z", changedAt: "2026-08-20T11:02:18Z", deletedAt: "2026-08-20T11:02:18Z" },
      signature: "PE executable",
      signatureMatchesExtension: true,
    },
    {
      recordId: "file-004",
      path: "/var/log/auth.log",
      name: "auth.log",
      parentPath: "/var/log",
      entryType: "file",
      extension: "log",
      sizeBytes: 94525,
      inode: "523010",
      allocationState: "allocated",
      macTimes: { modifiedAt: "2026-08-20T11:08:42Z", accessedAt: "2026-08-20T11:11:04Z", changedAt: "2026-08-20T11:08:42Z" },
      signature: null,
      signatureMatchesExtension: null,
    },
  ],
  findings: [
    {
      findingId: "finding-001",
      fileRecordId: "file-002",
      severity: "high",
      category: "signature",
      title: "Signature differs from extension",
      rationale: "update.jpg begins with an MZ header consistent with a PE executable, not a JPEG image.",
    },
    {
      findingId: "finding-002",
      fileRecordId: "file-003",
      severity: "medium",
      category: "recovery",
      title: "Deleted executable record",
      rationale: "remote_tool.exe is represented by an unallocated filesystem entry and retains timestamp metadata.",
    },
    {
      findingId: "finding-003",
      fileRecordId: "file-003",
      severity: "medium",
      category: "extension",
      title: "Potentially executable extension",
      rationale: "The .exe extension is commonly associated with executable content and merits correlation with execution artefacts.",
    },
  ],
  timeline: [
    { eventId: "evt-001", fileRecordId: "file-001", eventType: "created", occurredAt: "2026-08-20T10:31:14Z", path: "/home/analyst/Notes/launch_plan.pdf", source: "filesystem creation timestamp" },
    { eventId: "evt-002", fileRecordId: "file-002", eventType: "created", occurredAt: "2026-08-20T10:42:31Z", path: "/home/analyst/.cache/update.jpg", source: "filesystem creation timestamp" },
    { eventId: "evt-003", fileRecordId: "file-001", eventType: "modified", occurredAt: "2026-08-20T10:45:08Z", path: "/home/analyst/Notes/launch_plan.pdf", source: "filesystem modification timestamp" },
    { eventId: "evt-004", fileRecordId: "file-003", eventType: "created", occurredAt: "2026-08-20T10:49:27Z", path: "/home/analyst/Downloads/remote_tool.exe", source: "filesystem creation timestamp" },
    { eventId: "evt-005", fileRecordId: "file-003", eventType: "modified", occurredAt: "2026-08-20T10:54:59Z", path: "/home/analyst/Downloads/remote_tool.exe", source: "filesystem modification timestamp" },
    { eventId: "evt-006", fileRecordId: "file-003", eventType: "deleted", occurredAt: "2026-08-20T11:02:18Z", path: "/home/analyst/Downloads/remote_tool.exe", source: "derived from unallocated metadata" },
    { eventId: "evt-007", fileRecordId: "file-004", eventType: "modified", occurredAt: "2026-08-20T11:08:42Z", path: "/var/log/auth.log", source: "filesystem modification timestamp" },
  ],
};

export function getForensicWorkspace(): ForensicCaseWorkspace {
  return workspaceFixture;
}
