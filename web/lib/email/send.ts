export interface SendEmailInput {
  to: string;
  subject: string;
  text: string;
  html?: string;
}

// Optional Resend integration. When RESEND_API_KEY is unset, logs and returns false.
export async function sendEmail(input: SendEmailInput): Promise<boolean> {
  const apiKey = process.env.RESEND_API_KEY;
  const from = process.env.RESEND_FROM ?? "Thugir Scanner <alerts@thugirlabs.com>";

  if (!apiKey) {
    console.info("[email] skipped (RESEND_API_KEY unset):", input.subject, "→", input.to);
    return false;
  }

  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      from,
      to: [input.to],
      subject: input.subject,
      text: input.text,
      html: input.html ?? undefined
    })
  });

  if (!res.ok) {
    const body = await res.text();
    console.error("[email] Resend error:", res.status, body);
    return false;
  }
  return true;
}
