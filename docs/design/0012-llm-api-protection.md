# 0012 — Protecting LLM APIs

- Status: Draft
- Date: 2026-11-21
- Updated: 2026-11-21
- Owner: noureldin
- Depends on: [0001 — Performance-First Architecture](0001-performance-first-architecture.md),
  [0006 — Adapter Protocols Primer](0006-adapter-protocols.md),
  [0009 — Rate Limits](0009-rate-limits.md)

Many teams serve a large language model (LLM) API through their ingress: an OpenAI-compatible
server (vLLM, Ollama, LiteLLM, llama.cpp), a gateway in front of a provider, or their own chat
application. This document decides what Inkwall, a WAF next to the proxy, does for those APIs,
checked item by item against the [OWASP Top 10 for LLM Applications
2025](https://genai.owasp.org/llm-top-10/): a parser for the common request and response shapes,
cheap request caps, optional prompt-injection signatures, leak checks on responses (streamed ones
too), and rate limits weighted by tokens. It also says plainly what a WAF can't do and who should.
**Nothing here is built yet** (#277).

[Terms](../glossary.md) used here:

- **Engine:** `inkwall-engine`, the process that inspects requests and returns verdicts.
- **Policy:** a `WAFPolicy`. **Bundle:** the signed snapshot of all policies engines enforce.
- **Endpoint:** a path of a policy's routes that the policy declares as an LLM API, with its
  format ([§3](#3-api)).
- **Prompt text:** the strings of a request that the model reads: message contents, system
  instructions, tool results. **Output text:** the strings of a response the model wrote: message
  contents and tool-call arguments.
- **Check:** one LLM test with a stable ID (`llm-max-output-tokens`, `llm-secret-aws-key`), like a
  rule ([§9](#9-observability)).

## Contents

- [1. Goals and scope](#1-goals-and-scope)
- [2. The OWASP Top 10, item by item](#2-the-owasp-top-10-item-by-item)
- [3. API](#3-api)
  - [3.1 Fields](#31-fields)
  - [3.2 Formats and what is read](#32-formats-and-what-is-read)
  - [3.3 Body limits, skips and the rule sets](#33-body-limits-skips-and-the-rule-sets)
  - [3.4 Modes](#34-modes)
  - [3.5 Validation](#35-validation)
  - [3.6 Older engines](#36-older-engines)
- [4. Request checks](#4-request-checks)
  - [4.1 Parsing](#41-parsing)
  - [4.2 Caps, models, roles and tools](#42-caps-models-roles-and-tools)
  - [4.3 Injection signatures](#43-injection-signatures)
- [5. Response checks](#5-response-checks)
  - [5.1 Detectors](#51-detectors)
  - [5.2 Whole responses](#52-whole-responses)
  - [5.3 Streamed responses](#53-streamed-responses)
- [6. Token-weighted rate limits](#6-token-weighted-rate-limits)
- [7. Engine design](#7-engine-design)
  - [7.1 Where in the pipeline](#71-where-in-the-pipeline)
  - [7.2 Performance budget](#72-performance-budget)
  - [7.3 Bundle and API changes](#73-bundle-and-api-changes)
- [8. Through each proxy](#8-through-each-proxy)
- [9. Observability](#9-observability)
- [10. Failure modes](#10-failure-modes)
- [11. Security](#11-security)
- [12. Testing](#12-testing)
- [13. Rollout](#13-rollout)
- [14. Decisions](#14-decisions)
- [15. Open questions](#15-open-questions)

## 1. Goals and scope

A WAF sees the HTTP exchange: the JSON a client sends, the JSON or Server-Sent Events (SSE) the
model sends back. It doesn't see the model, the retrieval store, the tools the application runs or
what a user does with an answer. Within that, it can do four useful things cheaply:

- **Refuse requests that cost too much** before they reach the GPU: huge prompts, huge
  `max_tokens`, many choices, a model the route doesn't serve.
- **Enforce what clients may send:** no client-written system prompt, no client-defined tools.
- **Catch known leaks on the way out:** credentials, a canary planted in the system prompt,
  markdown images that exfiltrate data to another host.
- **Count tokens, not only requests,** per API key or tenant, with the rate limits of 0009.

Prompt-injection signatures are offered too, off by default and in `Detect` first: they catch the
copied, well-known attacks and nothing new. Inkwall doesn't claim to detect or stop prompt
injection, and the docs say so where the feature is turned on.

**In scope (phased, [§13](#13-rollout)):**

- `WAFPolicy.spec.llm`: endpoints and their formats, request checks, response checks ([§3](#3-api)).
- Formats: OpenAI Chat Completions, OpenAI Responses, OpenAI Embeddings, Anthropic Messages, and
  their SSE streams ([§3.2](#32-formats-and-what-is-read)).
- A bounded JSON parser and native checks in a new package, `pkg/llm`, not SecLang
  ([§7.2](#72-performance-budget) says why).
- `rateLimits[].cost: LLMTokens` ([§6](#6-token-weighted-rate-limits)).
- A benign and a malicious corpus, with a false-positive gate in CI ([§12](#12-testing)).

**Out of scope:**

- Anything that needs a model in the engine: classifiers, embeddings, "AI detection". A hook to an
  external classifier is [open question 3](#15-open-questions), not part of this design.
- Model-side defences: alignment, guard models, output grounding.
- RAG and vector stores, training data, fine-tuning, model supply chain.
- Rewriting traffic: redacting a response, lowering `max_tokens`. Inkwall allows, logs, denies or
  cuts; it doesn't edit bodies ([open question 2](#15-open-questions)).
- LLM APIs over WebSocket (OpenAI Realtime) or gRPC, Google's `generateContent` shape, and
  multimodal content (an injected prompt inside an image or audio is invisible to text checks).

## 2. The OWASP Top 10, item by item

| Risk | What Inkwall does | What it can't, and who should | False-positive risk |
|---|---|---|---|
| **LLM01:2025 Prompt Injection** | Optional signatures of known direct-injection and jailbreak phrasings in user prompt text, after normalisation ([§4.3](#43-injection-signatures)); refuses client-sent `system`/`developer` messages where the application adds its own ([§4.2](#42-caps-models-roles-and-tools)) | Novel or paraphrased attacks, other languages, indirect injection through retrieved documents, web pages or tool results the application fetches itself (the WAF never sees them). The application: least privilege for the model, untrusted-content boundaries, a guard model if needed | **High** for signatures: security teaching, fiction, red-team prompts, pasted articles about injection. Hence `Detect` by default. **Low** for the role check |
| **LLM02:2025 Sensitive Information Disclosure** | Credential detectors with fixed prefixes and checksums on output text; optional PII detectors (email, card numbers with Luhn, IBAN with its checksum) ([§5.1](#51-detectors)) | Disclosure in prose ("the CEO's salary is…"), data the model was trained on, anything without a pattern. The application and the data owner: what the model may read | **Low** for prefixed credentials; **medium to high** for PII: a support bot that repeats the user's own email is a match |
| **LLM03:2025 Supply Chain** | Nothing | Model provenance, weights, packages: the platform team (signed images, SBOMs, model registries) | — |
| **LLM04:2025 Data and Model Poisoning** | Nothing | Training and fine-tuning pipelines: whoever owns the data | — |
| **LLM05:2025 Improper Output Handling** | Flags `<script`, event-handler attributes and `javascript:` URLs in output text, and markdown images or links to hosts not allowed ([§5.1](#51-detectors)) | Escaping and sandboxing where the output is used (HTML, SQL, shell): the application. A WAF can't know which sink a string reaches | **High** for HTML: users ask models for code. Opt-in, for applications that render output as HTML. **Low** for image hosts, once allowed hosts are listed |
| **LLM06:2025 Excessive Agency** | Refuses client-defined tools, or allows only listed tool names, in requests; flags tool calls in responses to names not listed ([§4.2](#42-caps-models-roles-and-tools)) | What a tool may do, approvals for dangerous actions, the tools' own credentials: the application | **Low**: names are exact |
| **LLM07:2025 System Prompt Leakage** | A canary (a random string the application puts in its system prompt) and up to 8 fingerprints (distinctive sentences of it) matched in output text, also across stream events ([§5.3](#53-streamed-responses)) | A prompt leaked translated, encoded or paraphrased. The real fix is to keep secrets and authorization out of the system prompt: the application | **Very low** for a canary; **low** for fingerprints of 32 characters or more |
| **LLM08:2025 Vector and Embedding Weaknesses** | Caps on embedding requests (inputs per request, bytes), and token-weighted limits ([§6](#6-token-weighted-rate-limits)) | Poisoned documents, cross-tenant retrieval, embedding inversion: the retrieval layer | **Low** |
| **LLM09:2025 Misinformation** | Nothing | Grounding, citations, human review: the application | — |
| **LLM10:2025 Unbounded Consumption** | Body, prompt, message and choice caps; a `max_tokens` cap and an option to require one; a model allowlist; request and token-weighted rate limits per API key or tenant ([§4.2](#42-caps-models-roles-and-tools), [§6](#6-token-weighted-rate-limits)) | Exact token counts (Inkwall has no tokenizer: [§6](#6-token-weighted-rate-limits)), cost per provider, per-engine counting rather than cluster-wide ([0009 §2](0009-rate-limits.md#2-per-engine-limits-first)), queueing on the GPU: the serving layer | **Low**, once limits are sized from the `Detect` metrics |

## 3. API

```yaml
spec:
  mode: Block
  responses: {inspect: true, maxBytes: 1048576, streams: Inspect}   # for spec.llm.responses
  llm:
    endpoints:                       # required, at most 8
      - paths: ["/v1/chat/completions"]
        format: OpenAIChat
      - paths: ["/v1/messages"]
        format: AnthropicMessages
    maxBodyBytes: 1048576            # default 1 MiB
    ruleSetBody: Skip                # Skip (default) | Inspect
    request:
      models: ["llama-3.1-8b-instruct", "qwen2.5-*"]
      maxPromptBytes: 262144
      maxMessages: 256
      maxOutputTokens: 4096
      requireOutputTokens: true
      maxChoices: 1
      clientRoles: [user, assistant]  # default: every role
      tools: {allow: Listed, names: [search_docs, get_weather]}
      injection: {signatures: inkwall-v1, mode: Detect}
    responses:
      secrets: Inspect
      pii: [Email, PaymentCard]
      canaries: ["iwc-7f3a9c2e51d84b06"]
      fingerprints: ["You are the support assistant of Example Corp. Never discuss"]
      links: {allowedHosts: ["docs.example.com", "*.example-cdn.com"]}
      html: Inspect
      mode: Detect
  rateLimits:
    - name: tenant-tokens
      requests: 200000               # tokens per period, with cost: LLMTokens
      period: 1m
      cost: LLMTokens
      key: {header: {name: Authorization}}
```

### 3.1 Fields

| Field | Type | Default | Meaning |
|---|---|---|---|
| `endpoints[].paths` | `PathPattern` list, ≤ 16 | required | Paths of the policy's routes that are this format, matched like rate limits' `match.paths` ([0009 §3.1](0009-rate-limits.md#31-fields)) |
| `endpoints[].format` | enum, open set | required | `OpenAIChat`, `OpenAIResponses`, `OpenAIEmbeddings`, `AnthropicMessages` |
| `maxBodyBytes` | 1 KiB–10 MiB | 1 MiB | Body read on endpoints; over it: `body.onOversize` |
| `ruleSetBody` | `Skip`, `Inspect` | `Skip` | Whether the rule sets (CRS, SecLang) also get the JSON bodies of endpoints ([§3.3](#33-body-limits-skips-and-the-rule-sets)) |
| `request.models` | ≤ 64, exact or prefix `*` | any | The `model` values allowed |
| `request.maxPromptBytes` | 1–10 MiB | none | UTF-8 bytes of prompt text, all messages together |
| `request.maxMessages` | 1–100,000 | none | Messages, input items or embedding inputs |
| `request.maxOutputTokens` | 1–10,000,000 | none | Cap on the requested output tokens ([§4.2](#42-caps-models-roles-and-tools)) |
| `request.requireOutputTokens` | bool | false | Deny requests that set no output limit |
| `request.maxChoices` | 1–128 | none | Cap on `n` |
| `request.clientRoles` | set of `system`, `developer`, `user`, `assistant`, `tool` | all | Roles a client may send |
| `request.tools.allow` | `Any`, `None`, `Listed` | `Any` | Client-defined tools in requests; with `Listed`, also tool calls in responses |
| `request.tools.names` | ≤ 128 names | — | With `Listed` |
| `request.injection.signatures` | enum | off | `inkwall-v1`, the shipped, versioned set |
| `request.injection.mode` | `Detect`, `Block` | `Detect` | `Block` only on a `Block` policy |
| `request.mode` | `Detect` | the policy's | The other request checks log only |
| `responses.secrets` | `Inspect`, `Skip` | `Skip` | Credential detectors |
| `responses.pii` | set of `Email`, `PaymentCard`, `IBAN`, `USSocialSecurity` | none | PII detectors |
| `responses.canaries` | ≤ 4, 16–128 chars | none | Exact strings |
| `responses.fingerprints` | ≤ 8, 32–256 chars | none | Matched after normalisation ([§4.3](#43-injection-signatures)) |
| `responses.links.allowedHosts` | ≤ 64 host patterns | unset: no check | Markdown images and links to other hosts are flagged |
| `responses.html` | `Inspect`, `Skip` | `Skip` | Script and event-handler markup |
| `responses.mode` | `Detect` | the policy's | Response checks log only |

**Decision: a policy field, not only a rule set.** The checks need structure (which string is a
user's message, which number is `max_tokens`), a body limit of their own, an answer to
streaming, and a cost hook into rate limits. A `WAFRuleSet` can carry none of that; SecLang rules
over flattened JSON arguments would be slow and miss the roles. `spec.llm` lives in the policy for
the reason `rateLimits` does: it describes one application's endpoints and changes with them
([0009 §3.1](0009-rate-limits.md#31-fields)). The signature set is still data, versioned and
shipped in the engine image like `builtin: crs-v4`, selected by name.

Endpoints are declared, not guessed from the path. `/v1/chat/completions` is common, but Azure
OpenAI uses `/openai/deployments/{name}/chat/completions` and gateways rewrite paths. An endpoint
that isn't declared is an ordinary JSON API to the policy.

### 3.2 Formats and what is read

The parser reads only these fields; any other field is skipped unread, so new provider fields
don't break requests.

| Format | Prompt text | Output limit | Other fields read | Response output text and usage |
|---|---|---|---|---|
| `OpenAIChat` | `messages[].content` (string, or `text` parts), `messages[].tool_calls[].function.arguments`, by `role` | `max_completion_tokens`, else `max_tokens` | `model`, `n`, `stream`, `tools[].function.name`, `functions[].name` | `choices[].message.content`, `.tool_calls`; SSE `choices[].delta.content`, `.tool_calls`; `usage.prompt_tokens`, `completion_tokens` (in streams only with `stream_options.include_usage`) |
| `OpenAIResponses` | `instructions` (as `system`), `input` (string, or items' `input_text` parts, by `role`) | `max_output_tokens` | `model`, `stream`, `tools[].name` | `output[].content[].text`; SSE `response.output_text.delta`, `response.function_call_arguments.delta`; `usage.input_tokens`, `output_tokens` |
| `OpenAIEmbeddings` | `input` (string or array of strings; token arrays count as `4 ×` their length in bytes) | — | `model` | Not inspected (vectors) |
| `AnthropicMessages` | `system` (string or `text` blocks), `messages[].content` (string, `text`, `tool_result` blocks) | `max_tokens` (required by the API) | `model`, `stream`, `tools[].name` | `content[].text`, `tool_use.input`; SSE `content_block_delta` (`text_delta`, `input_json_delta`); `usage.input_tokens`, `output_tokens` |

Image, audio and document parts count toward `maxBodyBytes` and aren't inspected. The Responses
API's `previous_response_id` keeps history on the provider: Inkwall sees only the new turn, and
`maxMessages` counts only it.

### 3.3 Body limits, skips and the rule sets

LLM requests are large: a long chat history is easily 100 KiB, an agent's context several MiB.
The engine's default body limit is 64 KiB (`--max-body-bytes`), and the CRS on JSON costs about
100 ms per 8 KB ([0001 §3.1](0001-performance-first-architecture.md#31-measured-baseline-2026-10-03)).

- **Body limit.** `BodyLimit` (`pkg/pipeline/pipeline.go`) returns `maxBodyBytes` for an endpoint,
  instead of `body.maxBytes`. A body over it gets `body.onOversize` (413 in `Block` by default),
  like any body. The proxy's own buffer still bounds what reaches the engine ([§8](#8-through-each-proxy)).
- **The rule sets.** With `ruleSetBody: Skip`, the default, the rule sets inspect an endpoint's
  method, URI, headers and cookies, not its JSON body, and not its response body: the LLM checks
  own those. Prose and pasted code trip the CRS's SQL injection and XSS rules all the time, and
  the cost is out of every budget. `Inspect` keeps today's behaviour, for users who accept both.
  This is a change of behaviour for a route that adds `spec.llm`, and the field's description
  says so.
- **`skip.paths` and `skip.bodyPaths`** win over `llm`: a skipped body isn't read, so its LLM
  checks don't run. The webhook warns when an endpoint path is also in `skip.bodyPaths`.
- **`body.inspect: false`** turns off the rule sets' body inspection only; endpoints still read
  their bodies for the LLM checks.
- **Response size.** Whole responses are read up to `responses.maxBytes` (64 KiB default; 1 MiB
  recommended for LLM endpoints); stream events up to it each ([§5.3](#53-streamed-responses)).

### 3.4 Modes

`Detect` everywhere first, as with rate limits ([0009 §3.4](0009-rate-limits.md#34-modes-ip-lists-skips-and-exclusions)):
`request.mode` and `responses.mode` take only `Detect`, to log on a `Block` policy;
`injection.mode` defaults to `Detect` and takes `Block` only on a `Block` policy, so signatures
never block by surprise. Exclusions apply: each check has a stable rule ID in a range reserved for
Inkwall, 4,800,000–4,800,999 ([§9](#9-observability)), so `exclusions[].ruleIDs` with `when.path`
turns one off for one route. The webhook refuses that range in user SecLang rule sets.

### 3.5 Validation

Schema and CEL, as for 0009: at most 8 endpoints, their paths unique across endpoints; enums;
ranges above; `tools.names` required with `Listed` and refused otherwise; `injection.mode: Block`
needs `spec.mode: Block`; canaries and fingerprints of printable characters, unique;
`responses` checks need `spec.responses.inspect: true`; `cost: LLMTokens` on a rate limit needs
`spec.llm` and `match.paths` within its endpoints, or none. The webhook warns, not refuses, when
`responses.streams` is `Skip` while response checks are set: whole responses are checked,
streams aren't.

### 3.6 Older engines

`spec.llm` and `spec.rateLimits[].cost` join `requirement` in
`operator/internal/distribution/status.go` with the release that ships them (0.7.0 for phase 1,
[§13](#13-rollout)); later sub-fields get their own entry as they land. An older engine ignores
the field: the policy is `Enforced=False` with reason `EnginesOutdated`, and its rule sets keep
inspecting the bodies (the old engine doesn't know `ruleSetBody`), the safe side. An older engine
also ignores `cost` and counts each request as 1 token: a token limit would then allow up to
`requests` requests per period, which the `EnginesOutdated` message says.

## 4. Request checks

### 4.1 Parsing

`pkg/llm` parses the body once, with a streaming JSON tokenizer (no reflection, no
`map[string]any`), into a small fixed structure: the model, the numbers of §3.2, and the offsets of
prompt strings in the body, tagged with their role. Strings are unescaped into one pooled buffer
only when a check needs the text.

A body is **malformed** if it isn't valid JSON or UTF-8, nests deeper than 64, has a field §3.2
reads with another type, repeats a key along a path that is read (`"messages"` twice: Python and
Go keep the last, other parsers the first, and an attacker hides the real prompt in the one
Inkwall doesn't read), or has a `Content-Encoding` other than `identity` (the engine doesn't
decode request bodies). A malformed body is denied with 400 and the check `llm-malformed` in
`Block` mode, logged in `Detect`. Providers refuse such bodies anyway, so the false positives are
the parser's own bugs, which the fuzzers and the corpus look for ([§12](#12-testing)).

### 4.2 Caps, models, roles and tools

Each failed check denies with 400 (413 for the size caps), and the policy's `denyResponse`, in the
order of the table; the first decides.

| Check | Fails when |
|---|---|
| `llm-model` | `model` missing, or not in `models` (compared exactly, ASCII case-insensitive; a prefix ends in `*`) |
| `llm-max-prompt` | Prompt text over `maxPromptBytes` |
| `llm-max-messages` | More messages, items or inputs than `maxMessages` |
| `llm-max-choices` | `n` over `maxChoices` |
| `llm-max-output-tokens` | The output limit over `maxOutputTokens`, or absent with `requireOutputTokens` |
| `llm-client-role` | A message whose role isn't in `clientRoles` (`instructions` and Anthropic's `system` count as `system`) |
| `llm-tools` | Tools defined with `allow: None`, or a name not in `names` with `Listed` |

Inkwall caps but doesn't lower `max_tokens`: that would mean rewriting the body, which only
ext_proc could do. An absent output limit means the model's maximum for OpenAI; for public
endpoints the guide recommends `requireOutputTokens` with a cap.

`clientRoles` is the most useful LLM01 control a WAF has: most chat front ends add the system
prompt on the server, so a client that sends `system` or `developer` is overriding it. It is
useless for a gateway whose clients write their own system prompts, and the guide says so.

### 4.3 Injection signatures

`inkwall-v1` is a list of signatures, each a stable ID, a short description, literal anchors and an
optional bounded regular expression confirmed near an anchor. Families: instruction override
("ignore all previous instructions"), role and delimiter forgery (`<|im_start|>system`,
`[INST]`, `### System:` inside user text), well-known jailbreak preambles (DAN and its copies),
requests to reveal the system prompt, and long base64 or hex blobs in user text (a low-confidence
signature of its own). Matching runs over **user and tool-result text only**, never `assistant` or
`system` (the application's own), after normalisation: Unicode NFKC, case folding, removing
zero-width and bidirectional control characters, mapping a small table of confusable letters
(Cyrillic and Greek look-alikes) to Latin, and collapsing white space.

The engine matches all anchors in one pass (Aho–Corasick) and runs a signature's expression only
around an anchor's hit, so the cost is linear in the text and independent of the number of
signatures. A match logs the check `llm-injection-<family>` with the message index and the
offset, never the text ([§11](#11-security)).

What to expect, in the docs: the set catches copied attacks and lazy scanners. Anyone who
rephrases, translates or splits the attack gets past it. It is a signal for the SOC in `Detect`,
and a `Block` option for endpoints where its false positives were measured as acceptable.

The set is versioned (`inkwall-v1`, then `inkwall-v2`), never changed in place within a version
except to remove a signature found to misfire; adding signatures makes a new version, so an engine
upgrade doesn't change what a `Block` policy denies without the user choosing it.

## 5. Response checks

Response checks need response inspection: `responses.inspect: true`, and `streams: Inspect` for
SSE ([0006](0006-adapter-protocols.md#response-inspection-v040)). They read output text only, as
§3.2 lists, never the raw JSON.

### 5.1 Detectors

| Group | Checks | Match |
|---|---|---|
| `secrets` | AWS access key, GitHub, GitLab, Slack, Stripe live, OpenAI, Anthropic and Google API keys, PEM private key headers, JSON Web Tokens with a valid JSON header | A fixed prefix and the token's alphabet and length, its checksum where it has one (GitHub's CRC32). Known documentation examples (`AKIAIOSFODNN7EXAMPLE`) are excluded. No generic high-entropy detector: code samples are full of random-looking strings |
| `pii` | `Email`, `PaymentCard` (13–19 digits, Luhn, known issuer prefixes), `IBAN` (mod-97), `USSocialSecurity` (format and invalid ranges) | Each is opt-in |
| `canaries`, `fingerprints` | `llm-canary`, `llm-fingerprint` | Canaries exactly; fingerprints after the normalisation of §4.3 |
| `links` | `llm-link-host` | A markdown image `![…](url)` or link, or an HTML `<img src>`, whose host isn't allowed. Images matter most: a client renders them without a click, which is how injected prompts exfiltrate chat data to an attacker's server |
| `html` | `llm-html-script` | `<script`, `on…=` attributes in tags, `javascript:` and `data:text/html` URLs |

A check that matches in `Block` mode replaces a whole response with 403 or cuts a stream
([§5.3](#53-streamed-responses)); in `Detect` it logs. The verdict's reason is `llm`, its phase
`response`.

### 5.2 Whole responses

A response that isn't streamed is parsed with the same parser as requests, its output text
extracted, and the detectors run over each string. Usage (`usage.*_tokens`) settles token limits
([§6](#6-token-weighted-rate-limits)). A response that isn't JSON (an error page from a proxy, a
provider's HTML outage page) gets no LLM checks; the rule sets see it as today if `ruleSetBody`
is `Inspect`.

### 5.3 Streamed responses

Chat UIs stream. Today a policy with `streams: Inspect` evaluates each SSE event on its own, a
full rule evaluation per event (`Exchange.CheckEvent`, `pkg/pipeline/streams.go`). For an LLM
stream that fails twice: one event holds a token or two, so a key split over events is never seen
whole, and a 1,000-token answer costs 1,000 evaluations, about half a CPU-second with the CRS.

So on an endpoint, the engine reads each event's JSON, appends its output text (per choice, per
content block) to a **window** of the last 512 bytes, and runs the detectors incrementally: the
Aho–Corasick state carries across events, and a detector's expression runs on the window when an
anchor completes. Memory per stream: the windows and a few counters, under 2 KiB for one choice;
`n > 1` multiplies it, which `maxChoices` bounds. The rule sets don't run per event unless
`ruleSetBody: Inspect`.

**Holding back in `Block` mode.** A match is found only once its last byte arrives; the bytes
before it are in earlier events. In `Block` mode, the adapter already holds each event until it is
inspected (`HoldsEvents`); for endpoints the engine additionally holds the last **96 bytes** of
output text (the longest secret pattern; canaries ≤ 128 and fingerprints ≤ 256 are checked whole
up to that, and a longer match is caught with up to its length minus 96 bytes already sent). Held
events are released as soon as text after them rules out a match starting in them, and all at the
end of the stream. 96 bytes is about 25 tokens, a quarter to half a second at usual speeds: the
cost of not sending a key's first half before blocking its second. `Detect` mode forwards at once
and holds nothing. The hold-back size is [open question 4](#15-open-questions).

A match in `Block` cuts the stream, as today: the client has the events before it, never the
matching one, and a denial can't replace a response whose status went out
([denial responses](../denial-responses.md#which-denials-use-it)). The engine then ends the stream
with one last SSE event the client's SDK can read, `event: error` with a JSON body naming the
request ID, before closing.

A cut event (over `responses.maxBytes`) gets `responses.onOversize`. `data: [DONE]` and events the
parser doesn't know are passed through and counted, not inspected.

## 6. Token-weighted rate limits

LLM cost is in tokens. A limit of 60 requests a minute lets one client send 60 × 128k tokens. 0009
counts requests; this adds a cost per request, reusing its table, keys and answers unchanged.

`rateLimits[].cost`: `Requests` (default, 0009) or `LLMTokens`. With `LLMTokens`, `requests` and
`burst` are tokens, up to 1,000,000,000, and a request takes `n` tokens from its bucket in one step:
GCRA with a weight is the same algorithm, `tat + n × T − now > burst × T`
([0009 §3.2](0009-rate-limits.md#32-token-bucket-semantics)).

- **At request time** a request is charged an estimate: prompt bytes ÷ 3, rounded up, plus its
  output limit (or `maxOutputTokens`, or 4,096 when neither is set). Inkwall ships no tokenizer:
  tokenizers differ per model, cost megabytes and microseconds per KiB. Bytes ÷ 3 overestimates
  English (about 4 bytes a token) and is close for code and CJK text; the output limit is what
  the client asked for, the worst case.
- **At response time**, when the response is inspected and reports usage, the bucket is settled to
  the actual `input + output` tokens: the difference is refunded or added as debt (`TAT` moved
  back or forward, which `pkg/ratelimit` already does for refunds and 0009 planned for remote debt).
  A key in debt is refused before its body is read, as with request limits (`BodyLimit` returns 0).
  For streams, usage comes in the last event: OpenAI sends it only with
  `stream_options.include_usage`; without usage, output bytes ÷ 3 settle it.
- **Without response inspection** (Traefik, or `responses.inspect: false`) the estimate stands.
  The docs say this overcharges short answers to long limits, and to size limits from
  `inkwall_llm_tokens_total`.
- **Order.** Request-cost limits stay where 0009 put them, decided in `BodyLimit` before the body is
  read; token limits need the parsed body, so they run right after the LLM request checks,
  before the rules ([§7.1](#71-where-in-the-pipeline)). A request denied by a check isn't charged.

Keys don't change: client IP, or a header's hashed value ([0009 §3.3](0009-rate-limits.md#33-keys));
`Authorization` is a fine key, it is hashed and never stored. Per-tenant fairness needs the tenant
to be authenticated before Inkwall or the header to be one the client can't choose freely: the
0009 caveat applies unchanged. Limits stay per engine.

## 7. Engine design

### 7.1 Where in the pipeline

`Pipeline.check` (`pkg/pipeline/pipeline.go`) today: IP lists, the skip list, rate limits, the
WebSocket and gRPC checks, the rules; 0011 puts geo after the IP lists. With LLM endpoints:

1. IP lists; geo (0011); the skip list.
2. Request-cost rate limits (0009), decided in `BodyLimit`.
3. **LLM parse and request checks (new)**, for a request on an endpoint. Malformed or failed in
   `Block`: deny and stop. In `Detect`: remember and go on.
4. **Token-cost rate limits (new).**
5. WebSocket and gRPC checks, then the rules, without the endpoint's body when `ruleSetBody: Skip`.
6. Response: whole-response or per-event LLM checks, then the rules' response phase with the
   status and headers (and the body with `Inspect`).

Steps 3 and 4 run before an evaluation slot (`Admission`) is taken, like rate limits: they are
bounded by the body size and much cheaper than the rules ([§7.2](#72-performance-budget)), and a
flood of oversized prompts must not push other requests into `overload`. They run under the
policy's `timeout` like everything else. A request several policies inspect is parsed once; each
policy applies its own checks, and the strictest verdict wins. Endpoints resolve through
`router.UnambiguousPath`; a path that can't be read one way on a route with endpoints is treated
as an endpoint of every format of the policy and must parse as one of them, the counting side of
[0009 §3.1](0009-rate-limits.md#31-fields).

### 7.2 Performance budget

Native Go, not SecLang through Coraza: a few dozen signatures as SecLang rules over a 64 KiB
prompt would cost tens of milliseconds in Go's regexp engine, and the CRS on the same body far
more. Targets, on the reference machine of [0001 §3.1](0001-performance-first-architecture.md#31-measured-baseline-2026-10-03),
gated by `make bench-compare`, 0 allocations per request in steady state:

| Work | Target |
|---|---|
| Parse and request checks, 8 KiB chat body | ≤ 30 µs |
| The same, 1 MiB body | ≤ 2 ms (linear, about 1.5 ns per byte) |
| Injection signatures | ≤ 100 µs per 64 KiB of user text |
| One SSE event, all response detectors | ≤ 3 µs (today's per-event rule evaluation: about 500 µs) |
| Whole response, 16 KiB of output text | ≤ 40 µs |
| **Engine p99 added on an endpoint**, 32 KiB request, every check on, `ruleSetBody: Skip` | **≤ 300 µs**, inside the sidecar budget of [0001 §3](0001-performance-first-architecture.md#3-latency-budgets) |

The proxy still buffers and sends the body, which costs what it costs today; that is the
dominant term for MiB bodies over Unix sockets, and the guide says to size `maxBodyBytes` to the
real prompts.

### 7.3 Bundle and API changes

- **`api/bundle/v1/bundle.proto`:** `Policy.llm`, the next free field (16 is `deny_response`; geo
  takes the one after), a message `LLM` mirroring §3.1; `RateLimit.cost`.
- **`api/engine/v1/engine.proto`:** `REASON_LLM`, after geo's reasons; `pkg/pipeline` gains
  `ReasonLLM`, written `llm`.
- **`api/events/v1/events.proto`:** `SecurityEvent.llm` (`LLMEvent { format, model, check,
  message_index, role, offset, estimated_tokens, usage_tokens }`), the next free field. A check is
  also a `Match` with its reserved rule ID and an empty `snippet`. Operators before the release
  ignore it.
- **`pkg/llm`** (new): parser, normaliser, matchers, detectors, the signature set (embedded data,
  `inkwall-v1.yaml`). **`pkg/pipeline`:** endpoint lookup, steps 3–4, the stream windows on
  `Exchange`. **`pkg/ratelimit`:** a weighted `Take` and a `Settle`.
- **Operator:** CRD fields, CEL, webhook warnings, bundle builder, `requirement` entries, and the
  HAProxy effective-limit message ([§8](#8-through-each-proxy)).

## 8. Through each proxy

| Proxy | Requests | Whole responses | Streams | Limits to know |
|---|---|---|---|---|
| Traefik (forward-auth) | Yes | No (`ResponsesNotInspected`) | No | Bodies buffered up to 10 MiB + 1 by the operator's Buffering Middleware; token limits keep their estimates |
| Envoy Gateway, Istio (ext_proc) | Yes | Yes | Yes, with hold-back | The listener's buffer bounds the body Envoy sends (1 MiB per connection in the raw Envoy example, `docs/raw-envoy.md`) |
| Raw Envoy | Yes | Yes | Yes | As above; the user's own configuration |
| HAProxy (SPOE) | Up to `tune.bufsize` less `tune.maxrewrite`, about 15 KiB by default (`docs/haproxy.md`); the `Programmed` message names the effective limit, and the guide says to raise `tune.bufsize` | Up to the same buffer | No: HAProxy never sends streamed bodies (`ResponsesNotInspected`, as today) | A chat history over the buffer is oversized: `onOversize` |
| Standalone proxy, `/v1/check` | Yes | Proxy: yes; `/v1/check`: if the caller sends it | Proxy: yes | — |

Denials use the policy's `denyResponse` ([denial responses](../denial-responses.md)). The guide
gives an OpenAI-shaped error body (`{"error":{"message":…,"type":"invalid_request_error",
"code":"inkwall_denied"}}`) so SDKs show the message instead of a parse error, and notes that SDKs
retry 429 and 5xx (honouring `Retry-After`) but not 400 or 403.

## 9. Observability

**Metrics** (engine; bounded labels: `format` has 4 values, `check` a few dozen fixed IDs):

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `inkwall_llm_requests_total` | counter | `format`, `phase` | Requests and responses parsed on endpoints |
| `inkwall_llm_checks_total` | counter | `check`, `action` | Checks that matched: `deny`, `log`, `cut` |
| `inkwall_llm_malformed_total` | counter | `format`, `phase` | Bodies the parser refused |
| `inkwall_llm_tokens_total` | counter | `kind` | `estimated`, `settled_input`, `settled_output`: to size token limits |
| `inkwall_llm_inspect_seconds` | histogram | `phase` | Time in `pkg/llm`, against [§7.2](#72-performance-budget) |
| `inkwall_llm_streams_held_bytes` | gauge | | Output bytes held back now, over all streams |

No label by model (users choose model strings) or policy; per-policy counts come from the opt-in
`inkwall_policy_requests_total`, which gains the reason `llm`.

**Events.** A failed check is a security event with reason `llm`, the `LLMEvent` of §7.3 and a
`Match` with the check's reserved ID. Events carry no prompt or output text: no `snippet`, ever,
because the prompt is the user's data and the output match is the leaked secret
([0002 §8.3](0002-system-architecture.md#83-data-privacy)). `offset` and `message_index` let the
application find it in its own logs.

**`inkwallctl explain`** names the check, its cause and fix from the reasons registry
(`operator/reasons/reasons.go` gains `llm` and one entry per check), and `explain policy` lists the
endpoints, caps and token ceilings. `inkwallctl test --policy` accepts LLM request and response
bodies, and SSE streams as a list of events, so a policy's checks can be tested in CI.

**Status.** No new condition: older engines are `EnginesOutdated` ([§3.6](#36-older-engines)),
responses a proxy can't send are `ResponsesNotInspected`, and HAProxy's buffer is in
`Programmed`'s message, all as today.

## 10. Failure modes

| Situation | What happens |
|---|---|
| Body over `maxBodyBytes`, or cut at the proxy's buffer | `body.onOversize`: 413 in `Block`, logged and forwarded in `Detect` |
| Malformed request body | 400 `llm-malformed` in `Block`, logged in `Detect` ([§4.1](#41-parsing)) |
| Malformed response, or a stream event the parser can't read | Logged (`llm-malformed`, phase `response`) and passed: a provider's odd output isn't the client's attack, and cutting answers on parser bugs would hurt more than it protects |
| LLM checks exceed the policy's `timeout` | The failure mode, as for the rules (fail closed in `Block` by default) |
| Engine unreachable | The proxy's failure mode, as today; nothing LLM-specific |
| Stream client disconnects | Windows freed with the `Exchange`; tokens settled from the bytes seen |
| Engine restart mid-stream | The proxy's failure mode for the response phase; token buckets restart full (0009 §5.4) |
| Old engine | `EnginesOutdated`; rule sets inspect bodies as before |
| Signature set misfires after an upgrade | Can't happen silently: a version's signatures only shrink ([§4.3](#43-injection-signatures)) |

## 11. Security

- **Parser.** Bounded depth, bounded body, linear time, no recursion over attacker input, no
  allocation proportional to the number of keys. Duplicate keys on read paths and invalid UTF-8
  refuse the body, against parser differentials with the model server ([§4.1](#41-parsing)).
- **Matching.** Literal anchors and RE2 expressions confirmed in a bounded window: no
  backtracking, cost independent of the signatures' count.
- **Evasion, said plainly.** Normalisation removes the cheap tricks (zero-width characters,
  full-width letters, common look-alikes); it doesn't stop translation, paraphrase, encodings
  other than the flagged blobs, or attacks split across turns. Canaries are defeated by a leaked
  prompt that is rewritten. These are in the user guide, under the feature, not in a footnote.
- **Data.** Prompt and output text stay in the engine's memory for the request; events and logs
  carry IDs, offsets and counts. Canaries and fingerprints are in the policy and the bundle, which
  only the operator and the engines read; they aren't secrets in themselves, but they are
  redacted from `explain` output and the MCP server ([0008](0008-assistants.md)) to two characters.
- **No new path.** No network call, no model, no new component; the engine's attack surface grows
  by the parser, which is fuzzed.

## 12. Testing

| Layer | What | Where |
|---|---|---|
| Unit | Each format's fields of §3.2, strings and parts, unknown fields skipped, every malformed case of §4.1 (duplicate keys at each read path, wrong types, depth 65, invalid UTF-8, an encoded body); each request check at its boundary; roles, tools, model patterns | `pkg/llm` |
| Unit | Each detector: positives, the documented examples excluded, checksums; normalisation; window matching across every possible event split of a match; hold-back releases as early as allowed and never sends a matching byte in `Block` | `pkg/llm`, `pkg/pipeline` |
| Unit | Pipeline order of §7.1; `ruleSetBody: Skip` keeps the body from the rules; skips win; modes and exclusions by reserved ID; weighted GCRA, settlement refund and debt, debt refusing in `BodyLimit` | `pkg/pipeline`, `pkg/ratelimit` |
| Unit | CRD validation (each CEL rule), webhook warnings, `requirement`, bundle output | `operator/...` |
| Fuzz | The parser against `encoding/json` on valid inputs (same fields, same values), never panicking or over its bounds on any input; SSE splitting with the window detector equal to the detector on the whole text | `pkg/llm` |
| Benchmark | The targets of §7.2, gated by `make bench-compare` | `pkg/llm`, `pkg/pipeline` |
| Corpus | The false-positive plan below | `test/llm` |
| e2e on kind | Envoy Gateway, Istio, HAProxy and Traefik against a fake OpenAI-compatible server (a small Go server in `hack/kind`, streaming and not): caps deny with 400, a canary cuts a stream before it reaches the client in `Block` and logs in `Detect`, a token limit answers 429 and settles from usage, HAProxy and Traefik report `ResponsesNotInspected` for streams, an old engine `EnginesOutdated` | `hack/kind` |
| Soak | 200 concurrent streams of 2,000 tokens with response checks: engine memory flat, p99 within §7.2 | `hack/kind/soak.sh` |

**False-positive plan.** `test/llm/corpus` holds:

- **Benign prompts**, at least 20,000: a public conversation set with an Apache-2.0-compatible
  licence (OpenAssistant's `oasst1` is the first candidate; each dataset's licence is checked
  when imported, and none without one is used), plus a hand-written set of the hard cases: people
  asking about prompt injection and jailbreaks, security training, role-play and fiction, code
  review with "ignore" in comments, translation requests, pasted chat logs, prompts in ten
  languages.
- **Benign responses**, at least 5,000: code in many languages (random-looking strings, HTML,
  example keys), support answers that repeat contact details, markdown with images and links.
- **Attacks**: a public injection set under a compatible licence (deepset's `prompt-injections` is
  a candidate), and positives written for each signature, at least three each.

CI runs every check over the corpus and fails if a signature in `inkwall-v1` matches more than
0.1% of benign prompts on its own, if the set together matches more than 0.5%, or if a secret
detector matches any benign response. The detection rate on the attack set is measured and
published in the guide as it is, without a target: it will be modest, and saying so is the point.
A signature reported as misfiring in the field is removed in a patch release ([§4.3](#43-injection-signatures)).

## 13. Rollout

Each phase is usable on its own, with its own `requirement` entry and user guide section.

1. **v0.7.0, requests and cost:** `endpoints`, `maxBodyBytes`, `ruleSetBody`, the request checks
   of §4.2, `rateLimits[].cost: LLMTokens` with estimates and settlement on whole responses. This
   covers LLM10 and the cheap parts of LLM01 and LLM06; it needs no response streaming work.
2. **Response checks:** detectors on whole responses, then on SSE with windows and hold-back
   (Envoy Gateway and Istio first), and settlement from streamed usage. LLM02, LLM05, LLM07.
3. **Injection signatures:** `inkwall-v1` with the corpus gate, `Detect` by default, documented as
   experimental for one minor release.
4. **Later, each its own design if wanted:** an external classifier hook, redaction, more formats
   (Gemini, Realtime over WebSocket).

The docs get `docs/llm-apis.md` (user guide: a first policy, what each check catches and misses,
`Detect` first, sizing limits from the metrics), and entries in `docs/rate-limits.md`,
`docs/denial-responses.md`, `docs/monitoring.md` and `docs/upgrading.md`.

## 14. Decisions

| # | Decision | Rejected |
|---|---|---|
| 1 | `WAFPolicy.spec.llm` with declared endpoints and formats | A rule set and JSON body paths only; guessing endpoints from paths |
| 2 | Native parser and matchers in `pkg/llm` | SecLang rules over flattened JSON arguments |
| 3 | Rule sets skip endpoint bodies by default (`ruleSetBody: Skip`) | The CRS on prompts and token streams |
| 4 | Caps deny; nothing is rewritten | Lowering `max_tokens`; redaction (open question 2) |
| 5 | Duplicate keys, wrong types, invalid UTF-8 and encoded bodies are malformed and denied in `Block` | Lenient parsing |
| 6 | Signatures off by default, `Detect` by default, versioned, a version only shrinks | Signatures on by default; updates that add matches within a version |
| 7 | Signatures on user and tool-result text only, normalised | All text; raw text |
| 8 | Prefixed credential detectors; PII opt-in; no entropy detector | Generic secret scanning |
| 9 | Streams: incremental matching over a window, 96-byte hold-back in `Block` | Per-event rule evaluation; buffering whole streams |
| 10 | Token cost as a rate-limit option, estimated (bytes ÷ 3 + output limit) and settled from usage | A tokenizer in the engine; a separate token-limit API |
| 11 | Reserved rule IDs per check, so exclusions work | A separate exclusion syntax |
| 12 | Events carry no prompt or output text | Snippets of matches |
| 13 | No model, no network call in the engine | A built-in classifier |

## 15. Open questions

1. **The token estimate.** Is bytes ÷ 3 the right default, or should a limit choose its
   divisor? *Recommendation:* fixed ÷ 3 in phase 1; revisit with
   `inkwall_llm_tokens_total` data from users.
2. **Redaction.** Replacing a matched secret with `[redacted]` instead of cutting the stream is
   what users will ask for, and only ext_proc can rewrite bodies. *Recommendation:* not in this
   design; a follow-up for Envoy-based proxies only, once cutting is proven.
3. **An external classifier hook.** Calling a guard model (Llama Guard, a provider's moderation
   API) from the engine adds 10–100 ms and a network dependency on the hot path.
   *Recommendation:* no; document how to chain a guard model behind Inkwall in the gateway
   instead, and revisit only with a design of its own that keeps the engine's budgets.
4. **Hold-back size.** 96 bytes protects every shipped secret pattern whole; canaries and
   fingerprints may be longer. *Recommendation:* fixed at 96 in phase 2, a policy field only if
   users ask, since longer hold-back is visible stutter in chat UIs.
5. **Who ships the default signatures.** Maintaining `inkwall-v1` is ongoing work, and its value
   is modest. *Recommendation:* ship a small, conservative set with the corpus gate in phase 3,
   and accept community signatures only with corpus results attached.
