export const payments = {
  async payout(p: { payee: string; amount: number; currency: string }) { return p; },
  async removePayee(id: string) { return id; },
  async mail(to: string, body: string) { return to + body; },
  async invoice(id: string) { return { id }; },
  async migrate(name: string) { return name; },
};
