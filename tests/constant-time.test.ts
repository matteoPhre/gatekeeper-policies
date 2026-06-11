import { describe, expect, it } from "vitest";
import { constantTimeEqual, constantTimeStringEqual } from "../src/utils/constant-time.js";

describe("constantTimeEqual", () => {
  it("returns true for equal string values", () => {
    expect(constantTimeEqual("secret-token", "secret-token")).toBe(true);
    expect(constantTimeStringEqual("secret-token", "secret-token")).toBe(true);
  });

  it("returns false for different string values", () => {
    expect(constantTimeEqual("secret-token", "secret-tokem")).toBe(false);
  });

  it("returns false for different lengths without throwing", () => {
    expect(constantTimeEqual("short", "much-longer-value")).toBe(false);
  });

  it("compares Uint8Array values", () => {
    const left = new Uint8Array([1, 2, 3]);
    const right = new Uint8Array([1, 2, 3]);
    const mismatch = new Uint8Array([1, 2, 4]);

    expect(constantTimeEqual(left, right)).toBe(true);
    expect(constantTimeEqual(left, mismatch)).toBe(false);
  });
});
