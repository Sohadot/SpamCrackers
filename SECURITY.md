# Security

SpamCrackers is a static site. It runs no server-side code, stores no user
data, and makes only two outbound requests, both user-initiated: DNS-over-HTTPS
lookups to `dns.google`, and waitlist submissions to `formspree.io`.

## What is enforced today (GitHub Pages)

Every page ships a `<meta http-equiv="Content-Security-Policy">` and a
`<meta name="referrer">`. These take effect in the browser on GitHub Pages,
where response headers cannot be customized. The policy allows only:

- `script-src` / `style-src`: `'self' 'unsafe-inline'` (the site's inline CSS/JS)
- `connect-src`: `'self' https://dns.google https://formspree.io`
- `img-src`: `'self' data:` · `object-src 'none'` · `base-uri 'self'`
- `form-action 'self' https://formspree.io` · `upgrade-insecure-requests`

## What still needs a real header (recommended)

Some controls only work as HTTP response headers and are therefore **not**
active on GitHub Pages. Because the domain's DNS is managed by Cloudflare,
the cleanest fix is to proxy the domain (orange-cloud) and add a Cloudflare
**Response Header Transform Rule** applying to all URLs on `spamcrackers.com`,
or migrate hosting to **Cloudflare Pages** (which reads `/_headers`). Values:

| Header | Value |
| --- | --- |
| `Strict-Transport-Security` | `max-age=31536000` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Cross-Origin-Opener-Policy` | `same-origin` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), payment=(), usb=()` |
| `Content-Security-Policy` | same policy as the per-page meta tag, plus `frame-ancestors 'none'` |

The full set is also written in `/_headers` for any host that reads it.
`frame-ancestors` and HSTS cannot be delivered via `<meta>`, so clickjacking
and TLS-pinning protection depend on this step.

## Reporting a concern

There is no dedicated security mailbox yet. Until one is published, please
report any concern through the contact/waitlist on
[spamcrackers.com](https://spamcrackers.com/#join). Model-governance and scope
are documented at
[/intelligence/governance/](https://spamcrackers.com/intelligence/governance/).
