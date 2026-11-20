import { describe, it, expect } from "vitest";
import { verdictFor } from "../src/verdict.js";

describe("verdictFor", () => {
  it.each([
    [0, "pookie"],
    [30, "pookie"],
    [31, "skeptical"],
    [69, "skeptical"],
    [70, "poltergeist"],
    [100, "poltergeist"],
  ])("%i -> %s", (score, verdict) => {
    expect(verdictFor(score)).toBe(verdict);
  });
});
