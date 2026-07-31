import { describe, expect, it } from "vitest";

import { advisorySummary, severityLabel } from "./App";

describe("severityLabel", () => {
  it("keeps deterministic risk labels", () => {
    expect(severityLabel(0)).toBe("Info");
    expect(severityLabel(4)).toBe("Critical");
  });
});

describe("advisorySummary", () => {
  it("keeps findings usable when AI is disabled", () => {
    expect(advisorySummary(undefined)).toBeNull();
  });

  it("labels model-generated content as advisory", () => {
    expect(advisorySummary({
      label: "AI-generated advisory",
      summary: "Review this path.",
      suggested_remediation: "Consider a guard.",
    })).toBe("AI-generated advisory: Review this path.");
  });
});
