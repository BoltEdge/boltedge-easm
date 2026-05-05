# SRS Module 01 — Authentication & Account Lifecycle

| Field | Value |
|---|---|
| Parent document | `02-srs.md` |
| Module ID | 01 |
| Status | Draft |
| Last reviewed | 2026-05-05 |

This module specifies how a person becomes a Nano EASM user, proves they are who they say they are, recovers from a forgotten credential, optionally hardens their account with multi-factor authentication, and eventually leaves the platform.

Cross-cutting NFRs from `02-srs.md` apply (NFR-SEC-001 through NFR-SEC-024 in particular). Module-specific FRs are below.

---

## FR-AUTH-001 — User registration via email + password

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]
**Source:** Charter §5.1

The system shall allow an unauthenticated visitor to create an account by providing first name, last name, email address, password (≥8 characters, see NFR-SEC-002), country, and accepting the Terms of Use, Privacy Policy, and Acceptable Use Policy.

**Acceptance criteria:**
- AC-1 Submission with valid input creates a `User` row with `email_verified=false` and a personal `Organization` with the registering user as `Owner`.
- AC-2 The system sends a verification email containing a tokenised link valid for 48 hours (see FR-AUTH-005).
- AC-3 The response carries `verificationRequired=true` and the user's email; **no session token is issued**.
- AC-4 Submission with an email address belonging to a verified account returns HTTP 409 with code `email already registered`.
- AC-5 Submission with an email address belonging to an *unverified* account whose verification token has expired (>48h since `email_verification_sent_at`) replaces the stale row with the new registration.
- AC-6 Submission with an email address belonging to an unverified account whose token is *still valid* returns HTTP 409 with code `UNVERIFIED_ACCOUNT_PENDING` and instructs the user to check their inbox or request resend.
- AC-7 The user's acceptance of legal documents is recorded (timestamp + version).

---

## FR-AUTH-002 — Verification email content and delivery

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The verification email shall:

**Acceptance criteria:**
- AC-1 Originate from `no-reply@nanoasm.com` via Resend (or the configured outbound provider).
- AC-2 Use the standard branded email shell.
- AC-3 Contain a single primary CTA button linking to `/verify-email?token=<token>` on the canonical frontend URL.
- AC-4 Include a fallback plain-text URL for clients that do not render HTML.
- AC-5 Clearly state the link's 48-hour expiry.
- AC-6 Carry a stable subject line ("Verify your Nano EASM email address" or a tightly-similar variant) for inbox-grouping behaviour.

---

## FR-AUTH-003 — Verification page requires explicit user click

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The `/verify-email` page shall **not** auto-fire the verification call on page load. It shall present a "Verify my email" button that the user must click to consume the token.

This requirement guards against email-security-gateway link prefetching (Microsoft Safe Links, Mimecast, Proofpoint, Gmail safe-browsing crawlers) auto-triggering verification on the recipient's behalf.

**Acceptance criteria:**
- AC-1 Loading `/verify-email?token=<token>` does not change `User.email_verified` or stamp `email_verification_sent_at`.
- AC-2 Only an explicit click on the page's verify button calls the backend `/auth/verify-email` POST endpoint.
- AC-3 The page handles the absence of `?token=` gracefully with a clear "missing token" message.

---

## FR-AUTH-004 — Verification token consumption

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

`POST /auth/verify-email` shall:

**Acceptance criteria:**
- AC-1 Accept a token in the request body.
- AC-2 Reject expired tokens (>48h) with HTTP 400 and code `VERIFICATION_INVALID`.
- AC-3 Reject malformed or signature-invalid tokens with HTTP 400 and code `VERIFICATION_INVALID`.
- AC-4 Reject tokens whose embedded email does not match the user's current email with HTTP 400.
- AC-5 If the user is already verified, return HTTP 200 with `alreadyVerified=true` (idempotent).
- AC-6 On success, set `email_verified=true` and audit-log `auth.email_verified`.
- AC-7 On success, **not** create a session; the user is redirected to login.

---

## FR-AUTH-005 — Resend verification

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

`POST /auth/resend-verification` shall:

**Acceptance criteria:**
- AC-1 Accept an email in the request body.
- AC-2 Always return a generic 200 response regardless of whether the email is registered, to avoid enumeration (NFR-SEC-017).
- AC-3 Throttle to ≤ 1 send per 5 minutes per email (NFR-SEC-012).
- AC-4 If the email belongs to a verified or suspended account, do nothing silently.
- AC-5 Otherwise issue a fresh token and dispatch a fresh verification email.
- AC-6 Update `email_verification_sent_at` on successful send.

---

## FR-AUTH-006 — Login via email + password

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

`POST /auth/login` shall:

**Acceptance criteria:**
- AC-1 Accept email + password.
- AC-2 Reject invalid credentials with HTTP 401, generic message ("invalid credentials"), no enumeration.
- AC-3 If the user is suspended, return HTTP 403 with code `ACCOUNT_SUSPENDED`.
- AC-4 If the user's organisation is suspended, return HTTP 403 with code `ACCOUNT_SUSPENDED`.
- AC-5 If the user's email is not verified, return HTTP 403 with code `EMAIL_NOT_VERIFIED` and the email.
- AC-6 If the user's organisation is on Free tier and `plan_status="expired"`, return HTTP 403 with code `FREE_TIER_EXPIRED` plus the grace-period end date (see Module 10).
- AC-7 If the user has MFA enabled, return HTTP 200 with `mfaRequired=true` and a short-lived MFA challenge token; do **not** issue a session token until MFA is satisfied (see FR-AUTH-013).
- AC-8 Otherwise issue a JWT access token, log `auth.login`, fire the welcome email if `welcome_email_sent_at IS NULL`, and return user + organisation context.

---

## FR-AUTH-007 — Logout

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The system shall provide a logout action that:

**Acceptance criteria:**
- AC-1 Discards the JWT and any client-side session state.
- AC-2 Audit-logs `auth.logout`.
- AC-3 Returns the user to the public landing page.
- AC-4 [BEYOND SPEC] If the user was impersonating another, restores the original superadmin session.

(Note: JWTs are stateless; "logout" is a client-side action. A server-side token revocation list is out of scope at this stage.)

---

## FR-AUTH-008 — Forgot password / reset request

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

`POST /auth/forgot-password` shall:

**Acceptance criteria:**
- AC-1 Accept an email address.
- AC-2 Always return a generic 200 response (NFR-SEC-017).
- AC-3 Throttle to ≤ 3 requests per hour per email (NFR-SEC-012).
- AC-4 If the email is registered and the account is active, generate a reset token valid for 24 hours and email a reset link.
- AC-5 Reset emails use the standard branded shell.

---

## FR-AUTH-009 — Password reset

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

`POST /auth/reset-password` shall:

**Acceptance criteria:**
- AC-1 Accept a token and a new password.
- AC-2 Reject expired or invalid tokens with HTTP 400.
- AC-3 Validate the new password against NFR-SEC-002.
- AC-4 Update the password hash, log `auth.password_reset`, and invalidate any other live sessions for the user [GAP — session invalidation requires a token revocation list, currently unimplemented].
- AC-5 Send a confirmation email noting "your password was reset" so the user can react if it wasn't them.

---

## FR-AUTH-010 — OAuth sign-up / sign-in via Google

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

`GET /auth/oauth/google` and the corresponding callback shall:

**Acceptance criteria:**
- AC-1 Redirect the user through Google's OAuth 2.0 consent flow.
- AC-2 On successful callback, look up the user by Google subject ID; if found, sign them in.
- AC-3 If the user is not found by subject ID but their Google email matches an existing user, link the OAuth identity to the existing account and sign them in (with `email_verified=true`).
- AC-4 If the user is not found at all, create a new `User` with `email_verified=true`, a personal `Organization`, and sign them in.
- AC-5 OAuth users do **not** receive the verification email (Google has already verified the email).
- AC-6 OAuth users **do** receive the welcome email on first successful sign-in.
- AC-7 Suspended users encountering OAuth callback are redirected to `/login?suspended=true`.
- AC-8 Bypass for the `EMAIL_NOT_VERIFIED` gate applies only to OAuth-issued sessions, not subsequent password logins.

---

## FR-AUTH-011 — OAuth sign-up / sign-in via Microsoft

**Priority:** P1 — Should
**Status:** [IMPLEMENTED]

`GET /auth/oauth/microsoft` and the corresponding callback shall behave identically to FR-AUTH-010 with Microsoft as the identity provider.

---

## FR-AUTH-012 — MFA enrolment (TOTP)

**Priority:** P0 — Must
**Status:** [GAP: not implemented]
**Source:** Charter §10 (regulatory expectations); industry baseline for SaaS handling sensitive scan data.

The system shall allow any authenticated user to enrol a TOTP-based second factor (RFC 6238). Specifically:

**Acceptance criteria:**
- AC-1 The user navigates to `/settings/account/mfa` and clicks "Enable MFA".
- AC-2 The system generates a fresh TOTP secret (≥ 160-bit entropy), stores it server-side encrypted at rest, and renders a QR code (`otpauth://` URI) plus the plaintext secret for manual entry.
- AC-3 The user enrols the secret in any compatible authenticator app (Google Authenticator, 1Password, Authy, etc.) and submits a fresh 6-digit code to confirm enrolment.
- AC-4 On successful confirmation, MFA is marked enabled for the user, and the system generates 10 single-use **recovery codes** (FR-AUTH-014).
- AC-5 Until enrolment is confirmed, the secret is held in a pending state and discarded after 15 minutes of inactivity.
- AC-6 An audit log entry `auth.mfa_enabled` is recorded.

---

## FR-AUTH-013 — MFA verification at login

**Priority:** P0 — Must
**Status:** [GAP: not implemented]

When a user with MFA enabled logs in, the system shall:

**Acceptance criteria:**
- AC-1 After successful password verification, return HTTP 200 with `mfaRequired=true` and a short-lived (5-minute) MFA challenge token; **no JWT is issued at this point**.
- AC-2 Accept a 6-digit TOTP code or a single-use recovery code via `POST /auth/mfa/verify`.
- AC-3 Validate TOTP codes against the user's stored secret with a ±1 step (30-second) skew tolerance.
- AC-4 Reject invalid codes with HTTP 401; rate-limit to ≤ 5 attempts per challenge token.
- AC-5 On success, issue the JWT and complete login (returning the same payload as FR-AUTH-006 success).
- AC-6 If a recovery code is used, mark it as consumed (one-time use); audit-log `auth.mfa_recovery_code_used`.
- AC-7 Audit-log every MFA verification attempt (success or failure).

---

## FR-AUTH-014 — MFA recovery codes

**Priority:** P0 — Must
**Status:** [GAP: not implemented]

The system shall provide one-time recovery codes for MFA fallback when the user loses access to their authenticator:

**Acceptance criteria:**
- AC-1 At MFA enrolment, generate 10 random codes, each at least 8 alphanumeric characters with sufficient entropy.
- AC-2 Display the codes to the user **once** at enrolment with a strong instruction to store them securely.
- AC-3 Store codes server-side as salted hashes (NFR-SEC-001-style).
- AC-4 Allow regeneration of the recovery code set via the MFA settings page; previous codes are invalidated.
- AC-5 Each code is single-use; verification (FR-AUTH-013) consumes the code on success.
- AC-6 If all 10 codes are consumed, prompt the user to regenerate before they lose them entirely.

---

## FR-AUTH-015 — MFA disable

**Priority:** P0 — Must
**Status:** [GAP: not implemented]

The system shall allow the user to disable MFA from `/settings/account/mfa` after re-authenticating with their password and providing a current TOTP code. Audit-log `auth.mfa_disabled`.

---

## FR-AUTH-016 — Required MFA for elevated roles

**Priority:** P1 — Should
**Status:** [GAP: not implemented]

The system shall allow an Organisation Owner to require MFA for all members of the organisation in roles Admin and above. When required:

**Acceptance criteria:**
- AC-1 Members without MFA enabled are redirected to the MFA enrolment page on next login and cannot use the app until enrolled.
- AC-2 Setting the requirement is audit-logged.
- AC-3 The requirement applies to OAuth-authenticated users (they still need a second factor on top of OAuth).

---

## FR-AUTH-017 — Required MFA for superadmin

**Priority:** P0 — Must
**Status:** [GAP: not implemented]

The system shall require MFA for every account with the `is_superadmin` flag. A superadmin without MFA enabled is blocked from the `/admin/*` console until they enrol.

**Acceptance criteria:**
- AC-1 The superadmin guard checks for MFA enrolment in addition to the flag.
- AC-2 An admin without MFA receives a 404 on every `/admin/*` route (consistent with the superadmin not-found behaviour) plus an in-app banner directing them to enrol.

---

## FR-AUTH-018 — Session inactivity timeout

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

See `NFR-SEC-006` (cross-reference). Browser sessions with no activity for 30 minutes shall require re-authentication.

---

## FR-AUTH-019 — Account self-deletion

**Priority:** P1 — Should
**Status:** [PARTIAL — currently delegated to organisation deletion via Owner]

A user shall be able to request deletion of their own account from `/settings/account`:

**Acceptance criteria:**
- AC-1 The user re-authenticates with their password (or MFA) before the deletion is accepted.
- AC-2 If the user is the sole Owner of their organisation, the deletion of the organisation is offered as part of the same flow.
- AC-3 If the user is a member of an organisation they do not own, the user is removed from that organisation but the organisation remains.
- AC-4 The user receives a confirmation email after deletion completes.
- AC-5 Audit log entries `auth.account_deleted` are written; the user_id reference in any retained audit row is set to NULL.
- AC-6 Deletion satisfies NFR-COMP-002 (right to erasure).

---

## FR-AUTH-020 — Impersonation by superadmin

**Priority:** P0 — Must (for support workflow)
**Status:** [IMPLEMENTED]

A superadmin shall be able to start an impersonation session for any non-superadmin user from the admin console:

**Acceptance criteria:**
- AC-1 Impersonation issues a session token for the target user and audit-logs `admin.user_impersonated`.
- AC-2 The impersonating session displays a persistent visual banner ("Impersonating <user> — Exit") on every page.
- AC-3 Exiting impersonation restores the superadmin's own session from client-side storage and redirects to `/admin/users`.
- AC-4 Superadmins cannot impersonate other superadmins.
- AC-5 Suspended users cannot be impersonated.

---

## FR-AUTH-021 — Welcome email after first verified login

**Priority:** P1 — Should
**Status:** [IMPLEMENTED]

The first successful login by a verified user shall trigger a one-time welcome email containing a quick-start guide. The email is idempotent (sent once per user, tracked via `welcome_email_sent_at`).

For invite-accepted users, the welcome email fires at invite acceptance, not at first login.
For OAuth users, the welcome email fires at OAuth-callback first sign-in.

---

## FR-AUTH-022 — Email change

**Priority:** P2 — Could
**Status:** [GAP: not implemented]

A user shall be able to change their primary email address from `/settings/account` by:

**Acceptance criteria:**
- AC-1 Entering the new address.
- AC-2 Receiving a verification email at the new address; the change does not take effect until that link is consumed via FR-AUTH-003 / FR-AUTH-004 flow.
- AC-3 The old address receives a notification email so the user can react if it wasn't them.
- AC-4 Until the new address is verified, the existing address remains the system-of-record.

---

*End of module 01.*
