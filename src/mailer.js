// ---------------------------------------------------------------------------
// E-mail is PREPARED but not switched on yet. Verification and password-reset
// routes already exist (they answer 501 "email_not_configured"), the
// auth_email_tokens table exists, and accounts have an email_verified flag.
//
// When a sending provider is chosen, implement `send()` below (for example
// with Resend or Brevo over their HTTP API using fetch) and set
// MAIL_PROVIDER, then fill in the 501 routes in routes/auth.js. Nothing else
// in the server has to change.
// ---------------------------------------------------------------------------

export const mailEnabled = () => !!process.env.MAIL_PROVIDER;

export async function send({ to, subject, text }) {
  if (!mailEnabled()) return { sent: false, reason: 'email_not_configured' };
  // TODO(email): call the chosen provider's API here.
  return { sent: false, reason: 'provider_not_implemented' };
}
