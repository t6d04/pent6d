---
name: html-injection
description: Server-rendered markup injection analysis distinct from script-executing cross-site scripting
---

# HTML Injection

HTML injection is untrusted input interpreted as markup without necessarily
executing JavaScript. It can alter user-visible content, forms, links, or
security-relevant workflow cues.

## Assess

- Reflection in emails, PDFs, admin consoles, rich-text views, templates, and
  response bodies.
- Sanitizer configuration, template escaping, URL rewriting, and attribute or
  tag context.
- Whether injected markup can create a credential-capture form, alter a trusted
  destination, or become script execution in a different renderer.

## Validation

Use a benign marker that proves the HTML context. Escalate to `xss` only when
script execution is demonstrably possible. Rate impact from the demonstrated
UI or workflow effect, not from hypothetical script execution.
