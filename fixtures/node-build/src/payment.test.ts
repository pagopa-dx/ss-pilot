import { describe, expect, it } from "vitest";

import { summarizePayments } from "./payment.js";

describe("summarizePayments", () => {
  it("summarizes synthetic payments without floating point currency arithmetic", () => {
    expect(
      summarizePayments([
        { amountCents: 1250, reference: "demo-001" },
        { amountCents: 375, reference: "demo-002" },
      ]),
    ).toEqual({ count: 2, totalCents: 1625 });
  });

  it("handles an empty batch", () => {
    expect(summarizePayments([])).toEqual({ count: 0, totalCents: 0 });
  });

  it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])(
    "rejects an invalid amount: %s",
    (amountCents) => {
      expect(() =>
        summarizePayments([{ amountCents, reference: "demo-invalid" }]),
      ).toThrow(RangeError);
    },
  );

  it("rejects duplicate references", () => {
    expect(() =>
      summarizePayments([
        { amountCents: 100, reference: "duplicate" },
        { amountCents: 200, reference: "duplicate" },
      ]),
    ).toThrow("unique");
  });

  it("rejects blank references", () => {
    expect(() =>
      summarizePayments([{ amountCents: 100, reference: " " }]),
    ).toThrow("nonempty");
  });

  it("rejects an overflowing total", () => {
    expect(() =>
      summarizePayments([
        { amountCents: Number.MAX_SAFE_INTEGER, reference: "max" },
        { amountCents: 1, reference: "extra" },
      ]),
    ).toThrow(RangeError);
  });
});
