import { SignJWT, jwtVerify } from "jose";
import { ENV } from "./_core/env";
import { storageGetSignedUrl } from "./storage";

export const MAX_EVIDENCE_BYTES = 512 * 1024 * 1024;

const allowedExtensions = new Set(["img", "dd", "raw", "e01", "vhd", "vhdx", "qcow2"]);

export type EvidenceIntake = {
  fileName: string;
  sizeBytes: number;
  mediaType: string;
};

type UploadReceipt = EvidenceIntake & {
  userId: number;
  caseId: string;
  objectKey: string;
};

function signingKey() {
  if (!ENV.cookieSecret) throw new Error("Upload receipts require the server signing secret");
  return new TextEncoder().encode(ENV.cookieSecret);
}

function filenameExtension(fileName: string) {
  const dot = fileName.lastIndexOf(".");
  return dot === -1 ? "" : fileName.slice(dot + 1).toLowerCase();
}

function safeFilename(fileName: string) {
  const normalized = fileName.trim().replace(/[\\/]+/g, "_").replace(/[^A-Za-z0-9._-]/g, "_");
  return normalized.replace(/^\.+/, "") || "evidence.img";
}

export function validateEvidenceIntake(input: EvidenceIntake): EvidenceIntake {
  const fileName = safeFilename(input.fileName);
  const extension = filenameExtension(fileName);
  if (!allowedExtensions.has(extension)) {
    throw new Error("Choose a supported disk image: .img, .dd, .raw, .e01, .vhd, .vhdx, or .qcow2");
  }
  if (!Number.isSafeInteger(input.sizeBytes) || input.sizeBytes <= 0 || input.sizeBytes > MAX_EVIDENCE_BYTES) {
    throw new Error("The dashboard intake limit is 512 MiB per disk image");
  }
  return { fileName, sizeBytes: input.sizeBytes, mediaType: input.mediaType || "application/octet-stream" };
}

async function signReceipt(receipt: UploadReceipt) {
  return new SignJWT(receipt)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("20m")
    .sign(signingKey());
}

async function verifyReceipt(token: string, userId: number): Promise<UploadReceipt> {
  const { payload } = await jwtVerify(token, signingKey(), { algorithms: ["HS256"] });
  if (payload.userId !== userId || typeof payload.objectKey !== "string" || typeof payload.caseId !== "string") {
    throw new Error("This upload receipt is not valid for the current investigator");
  }
  return {
    userId,
    caseId: payload.caseId,
    objectKey: payload.objectKey,
    fileName: String(payload.fileName),
    sizeBytes: Number(payload.sizeBytes),
    mediaType: String(payload.mediaType),
  };
}

async function createPresignedPut(objectKey: string, mediaType: string) {
  if (!ENV.forgeApiUrl || !ENV.forgeApiKey) throw new Error("Object storage is not configured for signed evidence uploads");
  const endpoint = new URL("v1/storage/presign/put", `${ENV.forgeApiUrl.replace(/\/+$/, "")}/`);
  endpoint.searchParams.set("path", objectKey);
  const response = await fetch(endpoint, {
    headers: { Authorization: `Bearer ${ENV.forgeApiKey}` },
  });
  if (!response.ok) throw new Error("Could not prepare the signed evidence upload");
  const payload = (await response.json()) as { url?: string };
  if (!payload.url) throw new Error("Storage did not return an upload URL");
  return { uploadUrl: payload.url, contentType: mediaType };
}

export async function issueEvidenceUpload(userId: number, input: EvidenceIntake) {
  const evidence = validateEvidenceIntake(input);
  const caseId = `case_${crypto.randomUUID().replace(/-/g, "")}`;
  const objectKey = `evidence/${userId}/${caseId}/${safeFilename(evidence.fileName)}`;
  const signedUpload = await createPresignedPut(objectKey, evidence.mediaType);
  const receipt = await signReceipt({ ...evidence, userId, caseId, objectKey });
  return { ...signedUpload, caseId, objectKey, receipt, expiresInSeconds: 1200 };
}

export async function completeEvidenceUpload(userId: number, receipt: string, sha256: string) {
  const evidence = await verifyReceipt(receipt, userId);
  if (!/^[a-f0-9]{64}$/i.test(sha256)) throw new Error("A valid SHA-256 digest is required to submit evidence");

  const workerUrl = ENV.forensicAnalysisUrl;
  if (!workerUrl) {
    return { caseId: evidence.caseId, status: "queued" as const, worker: "self-hosted worker not configured" };
  }

  const signedDownloadUrl = await storageGetSignedUrl(evidence.objectKey);
  const response = await fetch(`${workerUrl.replace(/\/+$/, "")}/v1/cases/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      case_id: evidence.caseId,
      image: {
        object_key: evidence.objectKey,
        original_name: evidence.fileName,
        sha256: sha256.toLowerCase(),
        size_bytes: evidence.sizeBytes,
        media_type: evidence.mediaType,
        signed_download_url: signedDownloadUrl,
      },
    }),
  });
  if (!response.ok) throw new Error("Evidence uploaded, but the self-hosted analysis worker did not accept the job");
  return { caseId: evidence.caseId, status: "queued" as const, worker: "submitted to self-hosted worker" };
}
