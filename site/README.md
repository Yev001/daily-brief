# Daily brief site

A phone-first checklist page on Cloudflare Workers + D1. Bots write sections through a bearer-token API; the owner ticks items on the page.

- `GET /` – the brief (requires a session cookie from the private login link, or a valid Cloudflare Access JWT).
- `GET /api/brief` – whole brief as JSON (Bearer token).
- `GET|PUT /api/section/<key>` – read / replace one section. Body: `{"items":[...], "label"?, "note"?, "image"?}` or a bare array.
- `POST /api/item/<id>/check` – body `{"checked": true|false}` (default true).

Section keys, in order: questions, weather, today, tomorrow, waiting, watching, school, health, shopping, work, projects, travel.

Item: `{id, kind: task|question|project|text|heading, text, indent?, link?, checked, checked_at, sub?: [items]}`.
`text` supports `**bold**` and `[label](https://...)`. Missing ids are generated. `checked_at` is kept automatically.

No secrets or personal data live in this repo: the Worker stores only SHA-256 hashes of its token and login key.
