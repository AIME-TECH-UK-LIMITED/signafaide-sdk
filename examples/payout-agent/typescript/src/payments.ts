/** A stand-in for a real payments client: it only says what it would do. */
export const payments = {
  async payout(p: { payee: string; amount: number; currency: string }): Promise<string> {
    return `paid ${p.amount} ${p.currency} to ${p.payee}`;
  },
};
