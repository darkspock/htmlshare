# htmlshare Product Specification

## Purpose

htmlshare has two primary use cases:

1. Fast AI publishing for short-lived review links.
2. Account-based sharing with access control, analytics, and legal proof.

The product must stay AI-first. A model that just generated an HTML explanation, report, prototype, or analysis should be able to publish it and immediately open or return a URL.

## Use Case 1: Fast AI Publishing

This is the default flow when a user is programming or working with an AI assistant and asks for a report, explanation, prototype, or similar HTML artifact.

Expected flow:

1. The user asks the AI to generate an HTML file or bundle.
2. The AI publishes it to htmlshare.
3. The AI opens or returns the URL.
4. The user sends the URL to a teammate for review.
5. The teammate can view it without registering.

This flow should not require email registration, OAuth, magic links, or account creation. The point is speed and low friction.

The AI registers or identifies itself by sending a unique session-scoped agent ID. The AI is responsible for generating, remembering, and reusing that ID during its session. htmlshare should treat this as an automation identity, not as a verified human account.

Fast AI publications should usually be short-lived. Recommended expiration is less than one week, and the API should make short TTLs easy to set.

Reader capabilities for this mode:

- Open the shared URL.
- Download the HTML bundle.
- Export or download as PDF when supported.
- Save to their own htmlshare account by creating a copy, if they are registered or choose to register.

Abuse controls are mandatory in this mode because it does not require a verified email:

- Rate limit by IP.
- Rate limit by agent ID.
- Limit publication size per request.
- Limit total storage per IP and per agent ID.
- Expire unclaimed or short-lived content automatically.
- Keep abuse reporting and moderation available.
- Block abusive IPs or agent IDs when limits or moderation rules are triggered.

## Use Case 2: Registered Sharing and Control

This flow is for users who want durable control over publication access and visibility.

Expected flow:

1. The user creates or opens an account with email or OAuth.
2. The user or their AI publishes an HTML bundle under that account.
3. The user chooses how it is shared.
4. The user can inspect visits, access logs, and recipients.

This flow should support:

- Account ownership.
- Longer-lived or manually managed publications.
- Access logs with timestamp, IP, path, user agent, authenticated email when known, and status.
- Visit counts.
- Sharing controls.
- Copying or saving publications to a registered user's own library.

Supported sharing modes:

- Link access: anyone with the link can open it.
- Specific recipients: only listed email addresses can open it.
- Domain recipients: allow-list entries such as `@example.com`.
- Signed access: the recipient receives a token by email, enters or opens it, and htmlshare records proof that the recipient accessed the publication.

Signed access must create an auditable record:

- Recipient email.
- Publication ID.
- Token ID or proof ID.
- Timestamp.
- IP address.
- User agent.

## Quotas and Limits

htmlshare must enforce limits to avoid saturating the system.

Required limits:

- Maximum size per publish request.
- Maximum number of files per publish request.
- Maximum size per individual file.
- Maximum total storage per unverified agent ID.
- Maximum total storage per IP for anonymous or fast AI publishing.
- Maximum total storage per registered account.
- Rate limits for publishing, sharing, signup, token creation, abuse submission, and downloads.

Limits should be configurable by environment variables so production can be tightened without code changes.

## Product Direction

The fast AI flow and the registered control flow are separate product modes. Do not force the fast flow through email registration. Do not remove the registered flow, because it is required for access control, analytics, recipient management, and legal proof.

The API should make the mode explicit so agents know whether they are creating a short-lived anonymous publication or a controlled account-owned publication.

Fast AI publishing can also support short-lived recipient-restricted sharing. If the user asks for a temporary file visible only to specific email recipients, the agent should be able to call `mode: "fast"` with `visibility: "recipients"` and `share.emails`; htmlshare sends magic links to those recipients and denies the public URL until the recipient proves email control. This must remain temporary and rate-limited. Registered mode is still required for account ownership, dashboard management, long-lived library storage, signed legal proof, broad analytics, and reusable agent keys.

## Implementation Plan

1. Replace the current whole-state persistence layer with SQLC-backed incremental queries and transactions.
2. Update the database schema for separate fast-agent publishing and registered account publishing.
3. Add the no-email fast publish flow using a session-scoped agent ID, short TTLs, rate limits, and storage quotas.
4. Keep and clean up the registered account flow for controlled sharing, access logs, recipients, domains, and signed access.
5. Add reader actions for download, PDF export when supported, and saving a copy into a registered account.
6. Update the public API, OpenAPI, MCP behavior, and `web/home/llms.txt` together so agents get the correct current instructions.
7. Update the React app copy and controls so the UI matches the two product modes instead of exposing internal implementation names.
