import { timingSafeEqual } from "node:crypto";

function toUint8Array(value: string | Uint8Array): Uint8Array {
  return typeof value === "string" ? Buffer.from(value, "utf8") : value;
}

export function constantTimeEqual(
  left: string | Uint8Array,
  right: string | Uint8Array,
): boolean {
  const leftBuffer = toUint8Array(left);
  const rightBuffer = toUint8Array(right);

  if (leftBuffer.length !== rightBuffer.length) {
    const maxLength = Math.max(leftBuffer.length, rightBuffer.length);
    const paddedLeft = Buffer.alloc(maxLength);
    const paddedRight = Buffer.alloc(maxLength);
    paddedLeft.set(leftBuffer);
    paddedRight.set(rightBuffer);

    timingSafeEqual(paddedLeft, paddedRight);
    return false;
  }

  return timingSafeEqual(leftBuffer, rightBuffer);
}

export function constantTimeStringEqual(left: string, right: string): boolean {
  return constantTimeEqual(left, right);
}
