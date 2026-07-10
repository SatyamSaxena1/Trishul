import { describe, expect, it } from "vitest";

import { severityLabel } from "./App";

describe("severityLabel", () => {
  it("keeps deterministic risk labels", () => {
    expect(severityLabel(0)).toBe("Info");
    expect(severityLabel(4)).toBe("Critical");
  });
});

