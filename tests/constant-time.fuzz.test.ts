import { describe, expect, it } from "vitest";
import { constantTimeEqual, constantTimeStringEqual } from "../src/utils/constant-time.js";

function nextSeed(seed: number): number {
  return (seed * 1664525 + 1013904223) >>> 0;
}

function makePseudoRandomBytes(seed: number, size: number): Uint8Array {
  let current = seed;
  const output = new Uint8Array(size);

  for (let index = 0; index < size; index += 1) {
    current = nextSeed(current);
    output[index] = current & 0xff;
  }

  return output;
}

describe("constant-time helpers fuzz coverage", () => {
  it("constantTimeEqual stays correct across random byte arrays", () => {
    let seed = 1337;

    for (let iteration = 0; iteration < 3000; iteration += 1) {
      seed = nextSeed(seed);
      const leftSize = seed % 96;
      seed = nextSeed(seed);
      const rightSize = seed % 96;

      const left = makePseudoRandomBytes(seed ^ 0x9e3779b9, leftSize);
      const right = makePseudoRandomBytes(seed ^ 0x85ebca6b, rightSize);

      const expected =
        left.length === right.length &&
        left.every((value, index) => value === right[index]);

      expect(constantTimeEqual(left, right)).toBe(expected);
    }
  });

  it("constantTimeStringEqual matches strict equality semantics", () => {
    let seed = 2026;

    for (let iteration = 0; iteration < 3000; iteration += 1) {
      seed = nextSeed(seed);
      const left = Buffer.from(
        makePseudoRandomBytes(seed ^ 0x27d4eb2f, seed % 48),
      ).toString("hex");
      seed = nextSeed(seed);
      const right = Buffer.from(
        makePseudoRandomBytes(seed ^ 0x165667b1, seed % 48),
      ).toString("hex");

      expect(constantTimeStringEqual(left, right)).toBe(left === right);
    }
  });
});
