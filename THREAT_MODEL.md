# Threat Model

This document describes the security boundaries, assumptions, and primary threats
for Starlette. Starlette is a lightweight ASGI framework/toolkit for building
Python web services. It provides request/response handling, routing,
middleware, static file serving, templating integration, WebSockets, background
tasks, and testing utilities.

The goal of this threat model is to make the project's security posture easier
to review and maintain. It is not a complete threat model for every application
built with Starlette.

## Scope

This threat model covers:

* Code shipped in the `starlette` package.
* HTTP, WebSocket, and lifespan handling exposed through the ASGI interface.
* Built-in middleware, including CORS, sessions, trusted hosts, HTTPS redirects,
  gzip, authentication integration, WSGI bridging, and error handling.
* Request parsing, response generation, static file serving, templating helpers,
  routing, background tasks, and test client behavior.
* Optional integrations documented by Starlette when they affect Starlette's
  security properties, such as `jinja2`, `itsdangerous`, `python-multipart`,
  `httpx`, and `pyyaml`.

This threat model does not cover:

* The complete security model of applications built on Starlette.
* ASGI servers, reverse proxies, load balancers, TLS termination, operating
  systems, container runtimes, databases, caches, queues, or identity providers.
* Third-party middleware and packages listed in the documentation.
* User-defined endpoint code, authentication backends, authorization rules,
  templates, static file contents, or deployment configuration.

## Assets

Starlette helps protect the following assets when applications use its APIs
correctly:

* Application control flow: route dispatch, middleware ordering, exception
  handling, and lifespan behavior.
* Request data: headers, cookies, query parameters, path parameters, body
  streams, uploaded files, and WebSocket messages.
* Response data: response bodies, headers, cookies, redirects, static files,
  streaming responses, and error responses.
* Session integrity: signed cookie contents produced by `SessionMiddleware`.
* Filesystem boundaries for `StaticFiles`.
* Availability of the application process when handling malformed or hostile requests.
* Developer expectations expressed by documented defaults and configuration options.

## Trust Boundaries

Starlette sits between untrusted clients and trusted application code.

Primary trust boundaries:

* Network to ASGI server: HTTP and WebSocket bytes are parsed by the ASGI server
  before Starlette receives ASGI events.
* ASGI server to Starlette: Starlette trusts the ASGI server to provide scopes
  and events that follow the ASGI specification, but it still treats client
  controlled values inside those events as untrusted.
* Starlette to application code: Starlette exposes parsed request data and calls
  user-defined endpoints, middleware, background tasks, and exception handlers.
* Starlette to optional dependencies: Starlette delegates selected behavior to
  packages such as `jinja2`, `itsdangerous`, `python-multipart`, `httpx`, and
  `pyyaml` when those features are installed and used.
* Starlette to filesystem: `StaticFiles`, template loading, file responses, and
  uploads interact with local files and temporary files.
* Browser to application: CORS, cookies, redirects, template escaping, and
  WebSocket behavior affect how browsers enforce security policies.

## Threat Actors

Relevant threat actors include:

* Remote unauthenticated clients sending crafted HTTP or WebSocket traffic.
* Authenticated users attempting privilege escalation or data exposure through application endpoints.
* Browsers executing cross-origin requests or attacker-controlled content.
* Operators or application authors who misconfigure security-sensitive options.
* Malicious or compromised third-party dependencies, middleware, or ASGI servers.
* Local users or build systems with access to application files, configuration,
  environment variables, package artifacts, or release credentials.

## Security Assumptions

Starlette's security posture relies on these assumptions:

* The ASGI server implements the ASGI specification correctly and applies its own
  protocol-level limits.
* Production deployments terminate TLS correctly, set trusted proxy headers only
  from trusted infrastructure, and do not expose development servers directly.
* Applications do not enable `debug=True` in production.
* Applications configure host, scheme, CORS, session, static file, upload, and
  authentication settings for their deployment.
* Session secret keys are high entropy, private, and rotated when compromise is
  suspected.
* User code validates authorization, input semantics, CSRF requirements, content
  security policy, rate limits, and business logic invariants.
* Optional dependencies are kept up to date and installed only when their
  features are required.

## Attack Surfaces and Mitigations

### ASGI Input Handling

Threats:

* Malformed scopes or event streams may trigger crashes or inconsistent state.
* Oversized or slow request bodies may consume memory, CPU, file descriptors, or
  worker capacity.
* Client-controlled URL, header, cookie, and query values may be used by
  application code without validation.

Mitigations:

* Starlette exposes streaming request-body APIs so applications can avoid loading
  large bodies into memory.
* Multipart parsing supports `max_files`, `max_fields`, and `max_part_size`
  limits to reduce denial-of-service risk.
* Invalid cookies are ignored rather than treated as trusted input.
* Starlette keeps a clear separation between raw ASGI data and higher-level
  request helpers.

Application responsibilities:

* Configure server-level limits for header size, body size, request timeouts,
  concurrency, and slow clients.
* Validate all client-controlled data before using it in authorization decisions,
  filesystem paths, redirects, templates, logs, subprocesses, database queries,
  or outbound requests.

### Routing, URLs, and Redirects

Threats:

* Host header attacks may poison absolute URL generation, redirects, password
  reset links, caches, or logs.
* Malformed `Host` headers may cause reconstructed URL components, such as
  `request.url.path`, to diverge from the ASGI `scope["path"]` that routing uses.
* Open redirects may be introduced by application code that reflects untrusted URLs.
* Path normalization mistakes may route requests unexpectedly.

Mitigations:

* URL reconstruction only uses syntactically valid `Host` header values.
* `TrustedHostMiddleware` can enforce an allowed `Host` header set.
* `HTTPSRedirectMiddleware` redirects HTTP and WS schemes to HTTPS and WSS.
* Routing uses structured path parameters and convertors.

Application responsibilities:

* Use `TrustedHostMiddleware` with explicit allowed hosts in production unless
  equivalent protection is enforced before Starlette. Its default
  `allowed_hosts=["*"]` configuration allows any host.
* Do not make authentication or authorization decisions from reconstructed URL
  strings such as `request.url.path`; prefer route structure, endpoint
  dependencies, `request.path_params`, or `request.scope["path"]` when the raw
  routed path is required.
* Validate redirect targets and avoid reflecting arbitrary user-supplied URLs.
* Configure proxy and scheme handling in the ASGI server or trusted middleware.

### Static Files and File Responses

Threats:

* Path traversal may expose files outside the configured static directory.
* Symlinks may bypass intended filesystem boundaries if enabled without care.
* Range requests and conditional responses may be abused for denial of service.
* Serving attacker-controlled files may enable stored XSS, content sniffing, or
  sensitive data disclosure.

Mitigations:

* `StaticFiles` confines lookups to configured directories and does not follow
  symlinks by default.
* `StaticFiles` returns 404 or 405 for unsupported paths or methods.
* Starlette has previously fixed security issues in static file traversal and
  range parsing; these areas should continue to receive focused review.

Application responsibilities:

* Serve only intended directories and packages.
* Avoid enabling `follow_symlink=True` unless the symlink targets are trusted.
* Do not place secrets, source files, build artifacts, or user uploads in public
  static directories.
* Set deployment-specific headers such as `Content-Security-Policy`,
  `X-Content-Type-Options`, and cache controls where required.

### Templates and HTML Responses

Threats:

* Cross-site scripting may occur when untrusted data is rendered into HTML,
  JavaScript, CSS, URLs, or attributes without correct escaping.
* Custom `jinja2.Environment` instances may disable autoescaping.
* Template loaders may expose unintended templates if pointed at broad
  directories.

Mitigations:

* `Jinja2Templates(directory=...)` enables autoescape by default for `.html`,
  `.htm`, and `.xml` templates.
* Starlette requires explicit template context construction by application code.

Application responsibilities:

* Keep autoescape enabled for HTML templates.
* Treat `markupsafe.Markup`, `|safe`, custom filters, and custom environment
  configuration as security-sensitive.
* Validate URL generation and apply CSP or other browser defenses as needed.

### Sessions and Cookies

Threats:

* Weak or leaked session secret keys allow attackers to forge session data.
* Signed cookie sessions protect integrity but not confidentiality.
* Missing cookie flags can expose sessions over insecure channels or in
  cross-site contexts.
* Large cookies can increase request size and resource use.

Mitigations:

* `SessionMiddleware` signs cookie-based sessions.
* Session cookies are set with `HttpOnly`.
* `same_site` defaults to `lax`.
* `https_only=True` sets the `Secure` flag for HTTPS deployments.

Application responsibilities:

* Use high-entropy secret keys and keep them private.
* Do not store secrets or sensitive personal data in Starlette's signed cookie
  sessions unless the application separately encrypts them.
* Set `https_only=True` in production HTTPS deployments.
* Configure cookie domain, path, SameSite policy, lifetime, and rotation strategy
  according to the application threat model.
* Add CSRF protection for state-changing browser endpoints when cookies are used
  for authentication.

### CORS and Browser Access Control

Threats:

* Overly broad CORS settings can expose authenticated APIs to attacker-controlled origins.
* Permissive origin regexes may match unexpected origins.
* Private Network Access may expose private-network services through browsers.

Mitigations:

* `CORSMiddleware` defaults are restrictive.
* Credentialed CORS should use explicit origins, methods, and headers rather
  than wildcards.
* `allow_private_network` defaults to `False`.
* Documentation warns against overly broad origin regexes.

Application responsibilities:

* Prefer explicit origins over wildcards or broad regexes.
* Do not combine `allow_origins=["*"]` with `allow_credentials=True` for
  authenticated browser APIs. Starlette reflects the request origin in this
  configuration so browsers can send credentials from any origin.
* Review credentialed CORS settings with the authentication model.
* Wrap the whole application when CORS headers must apply to error responses.

### Authentication and Authorization

Threats:

* Authentication backends may incorrectly parse credentials or treat invalid
  users as authenticated.
* Applications may assume authentication implies authorization.
* Middleware ordering may unintentionally bypass checks.

Mitigations:

* Starlette provides authentication integration points and exposes `request.user`
  and `request.auth`.
* Starlette does not implement application-specific authorization policy.

Application responsibilities:

* Implement and test authentication backends for malformed, missing, expired,
  replayed, and revoked credentials.
* Enforce authorization in endpoints, dependencies, middleware, or route
  structure.
* Ensure public routes, mounted applications, static files, and WebSockets have
  intended access controls.

### WebSockets

Threats:

* WebSocket connections may bypass HTTP-only assumptions in authentication,
  authorization, CSRF, CORS, or rate limiting.
* Long-lived connections can consume worker capacity.
* Untrusted message payloads may trigger parsing bugs or application-level
  injection.

Mitigations:

* Starlette exposes explicit WebSocket accept, receive, send, and close APIs.
* `HTTPSRedirectMiddleware` also redirects WS to WSS.
* `TrustedHostMiddleware` applies to WebSocket scopes.

Application responsibilities:

* Authenticate and authorize WebSocket connections before accepting them.
* Validate message size, schema, rate, and state transitions.
* Apply connection limits and idle timeouts at the ASGI server or proxy layer.

### Middleware and Exception Handling

Threats:

* Middleware order can change security behavior.
* Error responses may leak tracebacks, secrets, headers, or internal state.
* Stateful middleware may leak data between concurrent requests.
* Compression can increase side-channel risk when secrets and attacker input are
  compressed together.

Mitigations:

* Starlette documents middleware ordering and automatically wraps applications
  with `ServerErrorMiddleware` and `ExceptionMiddleware`.
* `debug=False` avoids traceback responses.
* Middleware documentation states that ASGI middleware should be stateless.
* `GZipMiddleware` avoids compressing server-sent events and responses that
  already specify `Content-Encoding`.

Application responsibilities:

* Keep `debug=False` in production.
* Review middleware order as part of security review.
* Avoid storing per-request mutable state on middleware instances.
* Avoid compressing responses that combine secrets with attacker-controlled
  reflected input when compression side channels are in scope.

### Background Tasks and Lifespan

Threats:

* Background tasks may perform privileged work after a response has been sent.
* Task failures may be missed by clients and operators.
* Lifespan code may expose secrets, initialize insecure defaults, or leave
  partial state after failure.

Mitigations:

* Starlette makes background tasks explicit response attachments.
* Lifespan hooks provide a structured startup and shutdown boundary.

Application responsibilities:

* Treat background tasks as trusted application code with explicit error
  handling and observability.
* Validate inputs before scheduling tasks.
* Ensure startup and shutdown code handles partial failures safely.

### WSGI Interoperability

Threats:

* Bridged WSGI applications may have different assumptions about concurrency,
  request bodies, headers, URL reconstruction, or thread-local state.
* Legacy WSGI applications may not be safe under ASGI deployment conditions.

Mitigations:

* WSGI support is isolated in Starlette's WSGI middleware.

Application responsibilities:

* Review mounted WSGI applications as separate trusted components.
* Validate proxy, path, scheme, and header behavior when bridging WSGI apps.

### Test Client

Threats:

* Tests may pass with defaults that differ from production, such as client
  address, scheme, host, proxy behavior, or installed middleware.
* Test-only configuration may accidentally be reused in production.

Mitigations:

* `TestClient` is explicitly documented as a testing utility built on `httpx`.

Application responsibilities:

* Test production-like host, scheme, cookie, CORS, authentication, and middleware
  settings.
* Avoid deriving production security settings from test defaults.

## Dependency and Supply Chain Risks

Threats:

* Vulnerabilities in required or optional dependencies may affect Starlette users
  when the vulnerable behavior is reachable through Starlette's supported APIs,
  documented integrations, or dependency constraints.
* Package publishing, CI, or repository compromise may distribute malicious
  releases.
* Optional dependencies may expand attack surface when installed unnecessarily.

Mitigations:

* Starlette has few required dependencies.
* Optional dependencies are declared separately.
* CI includes tests, type checking, linting, and GitHub Actions security scanning.

Project responsibilities:

* Evaluate whether dependency vulnerabilities are actually reachable through
  Starlette. A vulnerability in a dependency should usually be addressed by
  upgrading that dependency in the user's environment, not by raising
  Starlette's minimum supported dependency version.
* Adjust dependency constraints only when Starlette's declared constraints block
  users from installing a fixed dependency version, or when Starlette must use a
  newer dependency API to avoid exposing the vulnerable behavior.
* Review dependency changes, release workflows, and CI permissions.
* Prefer narrow CI permissions and trusted publishing practices.
* Document security-relevant dependency updates in release notes.

## Security Review Checklist

Security-sensitive changes should consider:

* Does this change parse, normalize, or trust client-controlled input?
* Does it affect routing, URL generation, redirects, hosts, schemes, or proxies?
* Can reconstructed URL data diverge from ASGI scope data used for routing?
* Does it read from or write to the filesystem?
* Does it change request body, multipart, upload, streaming, or range handling?
* Does it affect cookies, sessions, CORS, authentication, or middleware ordering?
* Does it change error handling, debug output, logging, or exception propagation?
* Does it introduce shared mutable state across requests?
* Does it add or update a dependency or release workflow?
* Are there tests for malformed, boundary-sized, concurrent, and unauthorized
  inputs?
* Does the documentation explain application responsibilities and insecure
  configurations?

## Known High-Risk Areas

The following areas deserve extra scrutiny because they are security-sensitive
and have historically produced vulnerabilities in web frameworks:

* Static file path normalization and symlink handling.
* `FileResponse` range and conditional request handling.
* Request body size, streaming behavior, multipart parsing limits, and temporary file behavior.
* Cookie parsing, signing, session serialization, and cookie flags.
* Host, scheme, proxy, redirect, reconstructed URL, and ASGI scope handling.
* CORS, Private Network Access, and credentialed browser requests.
* Debug and exception output.
* Middleware ordering and shared mutable state.
* WebSocket authentication, connection lifetime, and message validation.

## Reporting Security Issues

Please do not report suspected security vulnerabilities in public issues.
Report them privately through GitHub's security advisory for the Starlette repository.

## Maintenance

This threat model should be reviewed when:

* Starlette adds or substantially changes request parsing, response generation,
  static files, sessions, CORS, authentication, middleware, routing, WebSocket,
  or templating behavior.
* Dependency minimum versions or optional integrations change.
* CI, publishing, or release processes change.
* A security advisory is published.
