class _Payments:
    def payout(self, payee, amount, currency):
        return {"payee": payee, "amount": amount, "currency": currency}

    def remove_payee(self, payee_id):
        return payee_id

    def mail(self, to, body):
        return to + body

    def invoice(self, invoice_id):
        return {"id": invoice_id}

    def migrate(self, name):
        return name


payments = _Payments()
