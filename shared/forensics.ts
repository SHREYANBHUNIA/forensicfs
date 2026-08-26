export type CaseStatus = "queued" | "analyzing" | "complete" | "failed";
export type Severity = "info" | "low" | "medium" | "high";

export type ForensicFileRecord = {
  recordId: string;
  path: string;
  name: string;
  parentPath: string;
  entryType: "file" | "directory" | "link" | "other";
  extension?: string | null;
  sizeBytes: number;
  inode?: string | null;
  allocationState: "allocated" | "deleted" | "unknown";
  macTimes: {
    createdAt?: string | null;
    modifiedAt?: string | null;
    accessedAt?: string | null;
    changedAt?: string | null;
    deletedAt?: string | null;
  };
  signature?: string | null;
  signatureMatchesExtension?: boolean | null;
};

export type ForensicFinding = {
  findingId: string;
  fileRecordId?: string | null;
  severity: Severity;
  category: "signature" | "extension" | "metadata" | "recovery" | "timeline";
  title: string;
  rationale: string;
};

export type ForensicTimelineEvent = {
  eventId: string;
  fileRecordId?: string | null;
  eventType: "created" | "modified" | "accessed" | "changed" | "deleted";
  occurredAt: string;
  path: string;
  source: string;
};

export type ForensicCaseWorkspace = {
  caseId: string;
  displayName: string;
  status: CaseStatus;
  filesystemType?: string | null;
  evidence: { originalName: string; sha256: string; sizeBytes: number; objectKey: string };
  files: ForensicFileRecord[];
  findings: ForensicFinding[];
  timeline: ForensicTimelineEvent[];
};
