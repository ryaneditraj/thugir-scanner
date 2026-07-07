-- Prevent double-granting entitlements for the same Razorpay payment / subscription charge.
create unique index if not exists entitlements_razorpay_ref_uidx
  on entitlements (razorpay_ref)
  where razorpay_ref is not null;
