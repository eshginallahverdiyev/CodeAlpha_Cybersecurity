# 🧪 Mock Phishing Examples (For Training Purposes Only)

The examples below are **entirely fictional**. No real company, brand, or person is impersonated — they exist only to illustrate common phishing patterns and how to spot them.

---

## Example 1 — Fake "Account Suspension" Email

```
From:    IT-Support@secure-mail-alert.com
To:      you@company.com
Subject: URGENT: Your mailbox will be suspended in 24 hours!

Dear User,

We detected unusual activity on your account. Click the secure link
below within 24 hours to verify your identity or your account will
be permanently suspended.

[ Verify My Account ]

Thank you,
Security Team
```

**Why it's suspicious:**
| Red flag | Detail |
|---|---|
| Sender domain | `secure-mail-alert.com` is not the organization's real domain |
| Urgency | "24 hours" pressures quick action without thinking |
| Generic greeting | "Dear User" instead of the recipient's actual name |
| Vague signature | "Security Team" with no individual name or contact info |
| Call-to-action button | Hides the real destination URL until you hover over it |

---

## Example 2 — Fake Invoice / Payment Request (Spear Phishing / Whaling style)

```
From:    ceo.office@company-fnance.com
To:      accounts@company.com
Subject: Quick favor - urgent wire transfer

Hi,

I'm currently in a meeting and can't talk. I need you to process an
urgent wire transfer to a new vendor before end of day. Please
confirm you're available and I'll send the payment details.

Thanks,
[Executive Name]
```

**Why it's suspicious:**
| Red flag | Detail |
|---|---|
| Look-alike domain | `company-fnance.com` (missing the "i" in "finance") mimics the real domain |
| Urgency + secrecy | "Currently in a meeting", "before end of day" discourages verification |
| Unusual request | Wire transfers to a "new vendor" outside normal process |
| Authority pressure | Impersonates an executive to bypass normal scrutiny |

**Correct response:** Verify the request by calling the executive directly using a known phone number — never one provided in the email.

---

## Example 3 — Fake Delivery Notification (Smishing / SMS example)

```
SMS from: +1 (555) 019-2837
"Your package could not be delivered. Update your delivery
preferences here: http://trackpkg-delivery.info/update"
```

**Why it's suspicious:**
| Red flag | Detail |
|---|---|
| Unknown sender number | Not the courier's official short code |
| Unfamiliar domain | `trackpkg-delivery.info` — unofficial, non-standard domain |
| No order context | No tracking number, name, or order reference |
| Pressure to click | Vague threat of a failed delivery prompts an immediate tap |

---

## Example 4 — Fake IT Support Call (Vishing script pattern)

```
"Hello, this is IT Support. We've detected suspicious login
attempts on your account. To secure it, I need you to read me the
verification code we just texted to your phone."
```

**Why it's suspicious:**
| Red flag | Detail |
|---|---|
| Unsolicited contact | You did not initiate the call |
| Request for a one-time code | Legitimate IT/security teams never ask for OTPs or verification codes over the phone |
| Manufactured urgency | "Suspicious login attempts" pressures immediate compliance |
| No independent verification offered | A genuine caller will let you hang up and call back through an official number |

---

## 🎓 How to Use These Examples

- Walk through each example during a training session and ask participants to identify the red flags **before** revealing the annotated table.
- Adapt these templates into **simulated phishing exercises** (with proper authorization and using a dedicated phishing-simulation platform) to measure and improve real-world awareness.
- Pair this file with [`phishing_red_flags_checklist.md`](./phishing_red_flags_checklist.md) as a takeaway resource.
