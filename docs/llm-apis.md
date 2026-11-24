# LLM APIs

A policy's `llm` declares paths of its routes as LLM APIs: an OpenAI-compatible server (vLLM,
Ollama, LiteLLM, llama.cpp), a gateway in front of a provider, your own chat application. Their
request bodies are parsed strictly and checked natively, before the rules: the model, the
prompt's size, the number of messages and answers, the output limit a request asks for, the roles
a client sends and the tools it defines. A request that fails a check is denied with 400 (413 for
the size caps) in `Block` mode. These checks need engines 0.7.0 or later.

They refuse requests that cost too much before they reach the GPU, and requests that override
what your application controls (its system prompt, its tools). They don't detect prompt injection,
and nothing here claims to: see [What a WAF can't do](#what-a-waf-cant-do).

## Contents

- [A first policy](#a-first-policy)
- [Endpoints and formats](#endpoints-and-formats)
- [The rule sets and these bodies](#the-rule-sets-and-these-bodies)
- [The request checks](#the-request-checks)
- [Malformed bodies](#malformed-bodies)
- [Detect first](#detect-first)
- [When a check refuses a legitimate request](#when-a-check-refuses-a-legitimate-request)
- [Token limits](#token-limits)
- [Through each proxy](#through-each-proxy)
- [A denial SDKs can read](#a-denial-sdks-can-read)
- [Metrics and events](#metrics-and-events)
- [What a WAF can't do](#what-a-waf-cant-do)
- [Upgrading and rolling back](#upgrading-and-rolling-back)

## A first policy

A chat front end whose server adds the system prompt, serving two models, on a policy already in
`Block` mode, its LLM checks logging only while you watch them:

```yaml
apiVersion: waf.inkwall.dev/v1alpha1
kind: WAFPolicy
metadata: {name: chat, namespace: ai}
spec:
  targetRefs: [{group: gateway.networking.k8s.io, kind: HTTPRoute, name: llm}]
  mode: Block
  llm:
    endpoints:
      - paths: ["/v1/chat/completions"]
        format: OpenAIChat
    maxBodyBytes: 1048576            # 1 MiB, the default
    request:
      models: ["llama-3.1-8b-instruct", "qwen2.5-*"]
      maxPromptBytes: 262144
      maxMessages: 256
      maxOutputTokens: 4096
      requireOutputTokens: true
      maxChoices: 1
      clientRoles: [user, assistant]
      tools: {allow: None}
      mode: Detect                   # log first; remove to deny
```

Then watch the `llm` events and `inkwall_llm_checks_total` ([Metrics and
events](#metrics-and-events)) for a few days of real traffic, size the caps from what you see,
and remove `mode: Detect`.

## Endpoints and formats

`endpoints` lists up to 8 groups of paths, each with its format. Paths are exact (`/v1/messages`)
or prefixes ending in `*` (`/openai/deployments/*`), compared as [rate
limits'](rate-limits.md#which-requests-count) paths: in ASCII lower case, one trailing slash
ignored. Of an exact path and prefixes that match, the exact one decides, then the longest prefix.
A path in no endpoint is an ordinary route to the policy. Endpoints are declared, not guessed:
Azure OpenAI serves chat at `/openai/deployments/{name}/chat/completions`, and gateways rewrite
paths.

**List every path your server serves an API on**, or those paths get no checks: they are
ordinary routes. Servers answer the same API on several: LiteLLM's proxy serves chat at
`/chat/completions`, `/v1/chat/completions`, `/openai/deployments/{model}/chat/completions` and
`/engines/{model}/chat/completions`, and embeddings at `/embeddings` and `/v1/embeddings`; vLLM and
llama.cpp's server serve `/v1/...` and some unversioned aliases. Check your server's routes, or
prefer a prefix that covers them, and close the paths you don't serve at the proxy.

The parser reads only the fields below; every other field is checked to be valid JSON and skipped,
so new provider fields don't break requests.

| `format` | Prompt text | Output limit | Also read |
|---|---|---|---|
| `OpenAIChat` | `messages[].content` (a string, or `text` and `refusal` parts), `tool_calls[].function.arguments`, `function_call.arguments`, and the text servers give the model back with the history: `reasoning` (Ollama), `reasoning_content` (vLLM), `refusal`; by `role` | `max_completion_tokens` or `max_tokens` (the larger, when a request sets both) | `model`, `n`, `stream`, `tools[]`, `functions[]` |
| `OpenAIResponses` | `instructions` (as `system`), `input` (a string, or items' `input_text` and `output_text` parts, function calls' arguments and outputs), by `role` | `max_output_tokens` | `model`, `stream`, `tools[]` |
| `OpenAIEmbeddings` | `input` (a string, strings, or token arrays, counted 4 bytes a token) | none | `model` |
| `AnthropicMessages` | `system` (a string or `text` blocks), `messages[].content` (a string, `text`, `thinking` and `tool_result` blocks) | `max_tokens` | `model`, `stream`, `tools[]` |

Images, audio and files count toward `maxBodyBytes` only. The Responses API's
`previous_response_id` keeps the history on the provider: only the new turn is sent, and checked.
A request on an endpoint that sends no body (a `GET`) isn't checked.

A path the engine can't read one way (percent-encoded `/`, `;`, `//`, a dot segment, fullwidth
letters) is read every way an application or a proxy may read it. If one of those readings is an
endpoint, the request is checked as the formats of each such endpoint, and must parse as each;
the rule sets also keep reading its body, since another reading may route it to another
application. A path no reading of which is an endpoint is an ordinary route.

## The rule sets and these bodies

LLM requests are large and full of prose and pasted code, which trip the CRS's SQL injection and
XSS rules all the time; the CRS on a 32 KiB chat history takes about 200 ms. So with
`ruleSetBody: Skip`, the default, the rule sets inspect an endpoint's method, URI, headers and
cookies, and neither its request body nor its response body: the LLM checks own those. Attacks in
the URI and headers are still the rules'. **With `Skip`, nothing inspects the body's other
fields**: `user`, `metadata`, and any field your application adds to the request. If your
application reads such a field into a database or a page, validate it there, or use `Inspect`.

**This changes what a policy's rules read when you add `llm`.** `ruleSetBody: Inspect` keeps the
rules on the bodies too, up to `maxBodyBytes` (unless `body.inspect: false`), for an application
that echoes prompts into a database or a page and accepts the false positives and the latency.

`llm.maxBodyBytes` (1 KiB to 10 MiB, 1 MiB by default) replaces `body.maxBytes` on the endpoints,
and they're read also with `body.inspect: false`. A longer body gets `body.onOversize`: 413 in
`Block` mode by default. `skip.paths` and `skip.bodyPaths` win: a body that isn't read isn't
checked, and the webhook warns when they cover an endpoint.

## The request checks

`request` sets the checks; each is off unless set. Each failed check denies, in `Block` mode, in
this order, and the first decides:

| Check | Rule ID | Status | Fails when |
|---|---|---|---|
| `llm-malformed` | 4800000 | 400 | The body isn't one the parser reads one way ([below](#malformed-bodies)) |
| `llm-model` | 4800001 | 400 | `model` is missing, or not in `models` (exact or a prefix ending in `*`, compared in ASCII lower case) |
| `llm-max-prompt` | 4800002 | 413 | The prompt's text, every message together, is over `maxPromptBytes` (UTF-8 bytes) |
| `llm-max-messages` | 4800003 | 413 | More messages, input items or embedding inputs than `maxMessages` |
| `llm-max-choices` | 4800004 | 400 | `n` is over `maxChoices` |
| `llm-max-output-tokens` | 4800005 | 400 | The output limit is over `maxOutputTokens`, or absent with `requireOutputTokens` |
| `llm-client-role` | 4800006 | 400 | A message's role isn't in `clientRoles`; `instructions` and Anthropic's `system` are `system`, and a role none of `system`, `developer`, `user`, `assistant`, `tool` fails whenever `clientRoles` is set |
| `llm-tools` | 4800007 | 400 | The request defines a tool with `tools.allow: None`, or one not in `tools.names` with `Listed` (its name, or a built-in tool's type when it has none: `web_search_preview`) |

Inkwall caps but never lowers `max_tokens`: that would mean rewriting the body. Without an output
limit, OpenAI-compatible servers generate up to the model's maximum, so for public endpoints set
`requireOutputTokens` with a cap.

`clientRoles` is the most useful prompt-injection control a WAF has: a chat front end adds the
system prompt on its server, so a client that sends `system` or `developer` is overriding it. It
is useless for a gateway whose clients write their own system prompts (an SDK's agent, an IDE):
leave it unset there.

## Malformed bodies

A body is malformed (`llm-malformed`) if it isn't valid JSON or UTF-8, nests deeper than 64,
gives a field the checks read another type (`"max_tokens": "100"`, `"n": 1.5`; an integral float
such as `4096.0` is read as `4096`, as Python servers read it), repeats such a field in one object
(two `messages`: Python and Go keep the last, other parsers the first, and an attacker hides the
real prompt in the one Inkwall doesn't read), has a key that differs from a read one only in case
(`Messages`, `MAX_TOKENS`, or with a Kelvin sign for the `k`: servers in Go, such as Ollama,
match keys case-insensitively and keep the last), escapes a lone UTF-16 surrogate, or has a
`Content-Encoding` other than `identity` (the engine doesn't decode request bodies). A `null`
field is an absent one. The event's `llm.offset` is the byte where parsing stopped.

Model servers refuse such bodies too, so a malformed body from your own client is its bug. One a
server accepts is a parser bug: report it, and exclude 4800000 on its path meanwhile.

## Detect first

`request.mode: Detect` logs the requests that fail a check instead of denying them, on a `Block`
policy; on a `Detect` policy every check logs. `Block` isn't allowed there: the checks can't be
stricter than their policy. A rule's verdict wins over a logged check: the event is the rule's.

## When a check refuses a legitimate request

Raise the cap the event's `llm.check` names ([troubleshooting](troubleshooting.md#llm-checks)),
or turn the check off where it misfires by excluding its rule ID, on a path or the whole policy:

```yaml
  exclusions:
    - ruleIDs: [4800005]             # llm-max-output-tokens
      when: {path: /v1/chat/completions}
```

Exclusions narrowed to an argument, a cookie or a header don't apply to the LLM checks, and an
ambiguous path gets no path exclusion, as for the rules. Excluding 4800000 lets malformed bodies
through unchecked: the other checks can't read them. Rule sets can't use IDs 4,800,000 to
4,800,999: the webhook refuses them.

## Token limits

LLM cost is in tokens: 60 requests a minute lets one client send 60 × 128k tokens. A
[rate limit](rate-limits.md) with `cost: LLMTokens` counts tokens instead, per API key or tenant,
with the same keys, answers and `Detect` mode:

```yaml
  rateLimits:
    - name: tenant-tokens
      requests: 200000               # tokens per period
      period: 1m
      cost: LLMTokens
      key: {header: {name: Authorization}}
```

- **At request time**, once a request on an endpoint passed its checks, it takes its estimate at
  once from the bucket, or none: its prompt's bytes ÷ 3, rounded up, plus a floor for each part
  that isn't text, plus its output limit (or `maxOutputTokens`, or 4,096 when neither is set;
  embeddings have none), times `n` for an OpenAI Chat request asking for several choices.
  Inkwall has no tokenizer: bytes ÷ 3 overestimates English (about 4 bytes a token) and is close
  for code and CJK text; the output limit is what the client asked for, the worst case. A request
  a check denies isn't charged, and requests on other paths aren't counted.
- **Parts that aren't text** are charged a floor each, by kind, however they are sent (a URL, an
  ID, inline data), since their bytes don't tell their tokens. The floors are the least such a
  part costs at a common size, not the most: a whole response's usage settles the rest.

  | Part | Floor | Source |
  |---|---|---|
  | An image (`image_url`, `input_image`, Anthropic's `image`) | 1,600 | Anthropic's vision docs: about 1,600 tokens for the largest image it reads unscaled (about 1.15 megapixels, at width × height ÷ 750); OpenAI's high detail counts 1,445 for a 2048 × 768 image |
  | Audio (`input_audio`, a chat message's earlier `audio`) | 1,920 | A minute at the 32 tokens a second Google documents for Gemini; OpenAI's audio models count fewer |
  | A file or document (`file`, `input_file`, Anthropic's `document`) | 3,000 | One PDF page at the most Anthropic documents for a page's text (1,500 to 3,000 tokens), not counting the page's image |

- **A request that references state the server keeps** can't be estimated: a Responses request
  with `previous_response_id`, `conversation` or `prompt`, an `item_reference` input, a file by
  `file_id` (chat's `file.file_id`, `input_file`'s, a `document` whose `source` is of type
  `file`), Anthropic's `container_upload`. Each token limit charges it its whole burst (or its
  estimate, when that is more), so it is let through only on a full bucket; its response's usage
  settles it, refunding what it didn't use.
- **A body that can't be estimated** is charged as large as it may be, never nothing: a body cut
  at the limit (`onOversize: Allow`, or a proxy's smaller buffer), an encoded one with
  `llm-malformed` excluded, one the parser refuses while the checks only log (`detect`), or one
  not read at all (`skip.bodyPaths`). It takes its `Content-Length`, or `maxBodyBytes` when the
  body wasn't read whole and the `Content-Length` is missing or smaller (what was read doesn't
  tell its size), ÷ 3, rounded up, plus `maxOutputTokens`, or 4,096 when unset. With the default
  `maxBodyBytes` of 1 MiB that is about 350,000 tokens: a token limit with a smaller burst refuses
  such a request.
- **At response time**, when the policy inspects responses (`spec.responses.inspect: true`), the
  bucket is settled to the actual input and output tokens the response reports: the difference
  is refunded, or added as debt. A key in debt is refused, 429 with `Retry-After`, before its
  next body is read. A whole response settles by its `usage`; a streamed one (Server-Sent Events)
  by its usage events, read as the stream goes out, one event at a time, each up to
  `responses.maxBytes`: OpenAI Chat's last chunk (sent when the request sets
  `stream_options: {include_usage: true}`), the Responses API's `response.completed`, Anthropic's
  `message_start` and `message_delta`. A stream cut before its final usage (Anthropic's
  `message_start` came, its `message_delta` didn't) only adds debt, never refunds. A `usage` that
  repeats a key, or has one differing only in case (`Usage`, `PROMPT_TOKENS`, which a client in Go
  reads as the same), settles nothing: the estimate stands. The rules still don't read the
  response's body with `ruleSetBody: Skip`.
- **Without settlement** the estimate stands: through Traefik (which can't send responses),
  with `responses.inspect` off, for a whole response cut at `responses.maxBytes` (its `usage`
  comes last), for one encoded in `br` or `zstd` (the engine decodes only `gzip` and `deflate`),
  for a streamed answer through HAProxy (SPOE), the
  check endpoint, or Traefik, which don't stream bodies to the engine, for a usage event longer
  than `responses.maxBytes` (a `response.completed` holding a long answer), and for an OpenAI Chat
  stream without `include_usage`. Short answers to long output limits are then overcharged, and
  images, audio and files charged at their floors. Size the limit from
  `inkwall_llm_tokens_total`.
- **Requests in flight** are charged their estimates only: requests sent together, before the
  first of their responses settles, each take their estimate, and are owed the rest once they
  settle. A debt is owed in full, however many responses settle at once, up to an hour of the
  limit's rate (or two bursts, when the limit's window is longer than half an hour): one request
  that used far more than its estimate keeps its key out for up to about that hour.

`requests` and `burst` go up to 1,000,000,000 tokens; a burst so large that its window
(`burst` × `period` ÷ `requests`) wouldn't fit the engine's clock is cut to what does (a burst of a
billion at 1,000 tokens an hour is about 640 million). A token limit needs `spec.llm`, and its
`match.paths` must be the endpoints' paths or under their prefixes. Limits still count per engine
([what a limit means](rate-limits.md#what-a-limit-means)). Key a limit by the client's API key:
`x-api-key` for Anthropic's API, `Authorization` for OpenAI's and most OpenAI-compatible
servers. An `Authorization` key counts as servers read the header: its scheme in any case and
any spacing (`Bearer sk-1`, `bearer  sk-1`) is one key. A key is hashed, never stored. Per-tenant
fairness needs a key the client can't choose freely.

## Through each proxy

| Proxy | What to know |
|---|---|
| Envoy Gateway, Istio (ext_proc) | The operator raises the route's buffer to the largest `maxBodyBytes`, and sends the bodies even with `body.inspect: false`. Envoy's buffer and body mode are per route, not per path: every path of an HTTPRoute that has endpoints is buffered up to that limit and sent to the engine, also paths that aren't endpoints, which costs memory per request and latency on large uploads. Give the LLM API its own HTTPRoute, or a `sectionName` rule, to keep other paths as they were |
| Traefik (forward-auth) | The operator's Buffering Middleware sends bodies up to 10 MiB |
| HAProxy (SPOE) | HAProxy sends at most `tune.bufsize` less `tune.maxrewrite`, about 15 KiB by default: a longer chat history is oversized. The policy's `Programmed` message names the effective limit; raise `tune.bufsize` ([HAProxy](haproxy.md)) |
| Raw Envoy | Your own configuration: its buffer bounds the body ([raw Envoy](raw-envoy.md)) |
| The standalone proxy, `/v1/check` | Up to `--max-body-bytes` and the policy's limit |

The proxy still buffers the body and sends it to the engine, which is the dominant cost for MiB
bodies: size `maxBodyBytes` to your real prompts. Parsing and every check cost about 1 ns a byte
(8 µs for 8 KiB, 1 ms for 1 MiB), outside the evaluation slots the rules use.

## A denial SDKs can read

SDKs expect an error body they can parse. Give the policy an OpenAI-shaped
[`denyResponse`](denial-responses.md) so they show the message instead of a parse error:

```yaml
  denyResponse:
    contentType: application/json
    body: '{"error":{"message":"Refused by the gateway (request {{request_id}})","type":"invalid_request_error","code":"inkwall_denied"}}'
```

SDKs retry 429 and 5xx responses, honouring `Retry-After`, but not 400, 403 or 413: a refused
request fails at once.

## Metrics and events

The engine counts `inkwall_llm_requests_total` (by `format`), `inkwall_llm_malformed_total`,
`inkwall_llm_checks_total` (by `check` and `action`), `inkwall_llm_tokens_total` (`estimated`:
prompt bytes ÷ 3 plus the output limit, of the requests that passed; `settled_input` and
`settled_output`: what whole responses reported using) and
`inkwall_llm_inspect_seconds` ([monitoring](monitoring.md#engine)). None is labelled by model or
policy.

A failed check is a security event with reason `llm` and an `llm` object: the `check`, the
`format`, the `model`, the `message_index` (or the tool's index for `llm-tools`; -1 for the
request or a top-level field), the `role` for `llm-client-role`, the byte `offset` and the
`estimated_tokens`. Its match has the check's rule ID and no snippet. **Events carry no prompt
text**: the prompt is the user's data; the offset and the index find it in your own logs. With
`ruleSetBody: Inspect`, a rule that matches in an endpoint's request or response body has its
match logged without a snippet too, and a key of the body in the match's variable is cut at 32
bytes (the client chooses keys as well); matches in the URI and headers keep theirs. The `model`
is the client's text too: at most 64 bytes of it.

`inkwallctl explain request <request-id>` names the check, where it failed, its cause and fix,
and suggests the exclusion of its rule ID on the path (never `llm-malformed`'s), checked against
the policy; `inkwallctl tune` suggests those for many events at once, and `inkwallctl explain
policy` lists a policy's endpoints, checks and token limits ([testing
policies](testing-policies.md)).

## What a WAF can't do

Inkwall sees the HTTP exchange, not the model, the retrieval store or the tools your application
runs. Against the [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/):

| Risk | What these checks do | What they can't, and who should |
|---|---|---|
| LLM01 Prompt injection | Refuse client-sent `system` and `developer` messages where your server adds its own | Anything in user text, indirect injection through documents or tools your application fetches: your application (least privilege for the model, untrusted-content boundaries, a guard model) |
| LLM06 Excessive agency | Refuse client-defined tools, or allow only listed names | What a tool may do, approvals for dangerous actions: your application |
| LLM08 Vector and embedding weaknesses | Cap embedding inputs and bytes | Poisoned documents, cross-tenant retrieval: the retrieval layer |
| LLM10 Unbounded consumption | Cap the body, prompt, messages, choices and output limit; require one; allow only some models | Exact token counts, cost per provider, GPU queueing: the serving layer |
| LLM02, LLM03, LLM04, LLM05, LLM07, LLM09 | Nothing yet | Data, models and output handling: the application and its owners |

## Upgrading and rolling back

Upgrade the chart first, then the engines. An engine before 0.7.0 ignores `llm`: it checks none
of these requests, and its rule sets read their bodies as before, up to `body.maxBytes` (64 KiB
by default): a longer chat history gets `body.onOversize`, 413 in `Block` mode, until the engines
are upgraded. While one runs a policy with
`llm`, the policy is `Enforced=False`, reason `EnginesOutdated`, naming `spec.llm`. Rolling the
operator back below 0.7.0 drops the field.
