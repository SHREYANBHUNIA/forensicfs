import { describe, expect, it } from "vitest";
import type { ForensicTimelineEvent } from "./forensics";
import { filterTimeline } from "./timelineFilters";

const events: ForensicTimelineEvent[] = [
  { eventId: "evt-1", eventType: "created", occurredAt: "2026-08-20T10:31:00Z", path: "/case/report.pdf", source: "filesystem" },
  { eventId: "evt-2", eventType: "modified", occurredAt: "2026-08-20T10:45:00Z", path: "/case/report.pdf", source: "filesystem" },
  { eventId: "evt-3", eventType: "deleted", occurredAt: "2026-08-20T11:02:00Z", path: "/case/remote_tool.exe", source: "recovery" },
];

describe("filterTimeline", () => {
  it("isolates a selected forensic event type without reordering the chronology", () => {
    expect(filterTimeline(events, ["deleted"])).toEqual([events[2]]);
  });

  it("returns an empty list when all event filters are disabled", () => {
    expect(filterTimeline(events, [])).toEqual([]);
  });
});
