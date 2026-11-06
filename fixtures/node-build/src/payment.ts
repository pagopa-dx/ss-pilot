export interface Payment {
  amountCents: number;
  reference: string;
}

export function summarizePayments(payments: readonly Payment[]) {
  let totalCents = 0;
  const references = new Set<string>();
  for (const payment of payments) {
    if (!Number.isSafeInteger(payment.amountCents) || payment.amountCents <= 0) {
      throw new RangeError("Payment amounts must be positive safe integers");
    }
    if (payment.reference.trim() === "" || references.has(payment.reference)) {
      throw new Error("Payment references must be nonempty and unique");
    }
    references.add(payment.reference);
    totalCents += payment.amountCents;
    if (!Number.isSafeInteger(totalCents)) {
      throw new RangeError("Payment total exceeds the safe integer range");
    }
  }
  return { count: payments.length, totalCents };
}
