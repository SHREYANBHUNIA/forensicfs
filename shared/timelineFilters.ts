import type { ForensicTimelineEvent } from "./forensics";

export type TimelineEventType = ForensicTimelineEvent["eventType"];

export const timelineFilters: { id: TimelineEventType; label: string }[] = [
  { id: "created", label: "Created" },
  { id: "modified", label: "Modified" },
  { id: "accessed", label: "Accessed" },
  { id: "changed", label: "Metadata" },
  { id: "deleted", label: "Deleted" },
];

export function filterTimeline(
  events: ForensicTimelineEvent[],
  enabledEventTypes: TimelineEventType[]
) {
  return events.filter(event => enabledEventTypes.includes(event.eventType));
}
