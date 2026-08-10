import { describe, expect, it } from "vitest";

import { decisionLabel, decisionSeverity, isTerminalState, severityLabel } from "./App";

describe("severityLabel", () => {
  it("keeps deterministic risk labels", () => {
    expect(severityLabel(0)).toBe("Info");
    expect(severityLabel(4)).toBe("Critical");
  });
});

describe("decisionSeverity", () => {
  it("ranks a blocked deployment above one approved with actions", () => {
    expect(decisionSeverity("blocked")).toBeGreaterThan(decisionSeverity("approved_with_actions"));
    expect(decisionSeverity("approved")).toBe(0);
  });

  it("treats an unrecognised decision as needing attention rather than safe", () => {
    expect(decisionSeverity("something-new")).toBe(3);
  });
});

describe("decisionLabel", () => {
  it("renders machine decisions as prose", () => {
    expect(decisionLabel("approved_with_actions")).toBe("approved with actions");
  });
});

describe("isTerminalState", () => {
  it("keeps queued work visibly in progress and recognizes every terminal state", () => {
    expect(isTerminalState("queued")).toBe(false);
    expect(["completed", "failed", "cancelled"].every(isTerminalState)).toBe(true);
  });
});

