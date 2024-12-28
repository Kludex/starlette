---
toc_depth: 2
---

## 0.44.0 (December 28, 2024)

#### Added

* Add `client` parameter to `TestClient` [#2810](https://github.com/encode/starlette/pull/2810).
* Add `max_part_size` parameter to `Request.form()` [#2815](https://github.com/encode/starlette/pull/2815).

## 0.43.0 (December 25, 2024)

#### Removed

* Remove deprecated `allow_redirects` argument from `TestClient` [#2808](https://github.com/encode/starlette/pull/2808).

#### Added

* Make UUID path parameter conversion more flexible [#2806](https://github.com/encode/starlette/pull/2806).

## 0.42.0 (December 14, 2024)

#### Added

* Raise `ClientDisconnect` on `StreamingResponse` [#2732](https://github.com/encode/starlette/pull/2732).

#### Fixed

* Use ETag from headers when parsing If-Range in FileResponse [#2761](https://github.com/encode/starlette/pull/2761).
* Follow directory symlinks in `StaticFiles` when `follow_symlinks=True` [#2711](https://github.com/encode/starlette/pull/2711).
* Bump minimum `python-multipart` version to `0.0.18` [0ba8395](https://github.com/encode/starlette/commit/0ba83959e609bbd460966f092287df1bbd564cc6).
* Bump minimum `httpx` version to `0.27.0` [#2773](https://github.com/encode/starlette/pull/2773).

## 0.41.3 (November 18, 2024)

#### Fixed

* Exclude the query parameters from the `scope[raw_path]` on the `TestClient` [#2716](https://github.com/encode/starlette/pull/2716).
* Replace `dict` by `Mapping` on `HTTPException.headers` [#2749](https://github.com/encode/starlette/pull/2749).
* Correct middleware argument passing and improve factory pattern [#2752](https://github.com/encode/starlette/pull/2752).

## 0.41.2 (October 27, 2024)

#### Fixed

* Revert bump on `python-multipart` on `starlette[full]` extras [#2737](https://github.com/encode/starlette/pull/2737).

## 0.41.1 (October 24, 2024)

#### Fixed

* Bump minimum `python-multipart` version to `0.0.13` [#2734](https://github.com/encode/starlette/pull/2734).
* Change `python-multipart` import to `python_multipart` [#2733](https://github.com/encode/starlette/pull/2733).

## 0.41.0 (October 15, 2024)

#### Added

- Allow to raise `HTTPException` before `websocket.accept()` [#2725](https://github.com/encode/starlette/pull/2725).

## 0.40.0 (October 15, 2024)

This release fixes a Denial of service (DoS) via `multipart/form-data` requests.

You can view the full security advisory:
[GHSA-f96h-pmfr-66vw](https://github.com/encode/starlette/security/advisories/GHSA-f96h-pmfr-66vw)

#### Fixed

- Add `max_part_size` to `MultiPartParser` to limit the size of parts in `multipart/form-data`
  requests [fd038f3](https://github.com/encode/starlette/commit/fd038f3070c302bff17ef7d173dbb0b007617733).

## 0.39.2 (September 29, 2024)

#### Fixed

- Allow use of `request.url_for` when only "app" scope is available [#2672](https://github.com/encode/starlette/pull/2672).
- Fix internal type hints to support `python-multipart==0.0.12` [#2708](https://github.com/encode/starlette/pull/2708).

## 0.39.1 (September 25, 2024)

#### Fixed

- Avoid regex re-compilation in `responses.py` and `schemas.py` [#2700](https://github.com/encode/starlette/pull/2700).
- Improve performance of `get_route_path` by removing regular expression usage
  [#2701](https://github.com/encode/starlette/pull/2701).
- Consider `FileResponse.chunk_size` when handling multiple ranges [#2703](https://github.com/encode/starlette/pull/2703).
- Use `token_hex` for generating multipart boundary strings [#2702](https://github.com/encode/starlette/pull/2702).

## 0.39.0 (September 23, 2024)

#### Added

* Add support for [HTTP Range](https://developer.mozilla.org/en-US/docs/Web/HTTP/Range_requests) to
  `FileResponse` [#2697](https://github.com/encode/starlette/pull/2697).

## 0.38.6 (September 22, 2024)

#### Fixed

* Close unclosed `MemoryObjectReceiveStream` in `TestClient` [#2693](https://github.com/encode/starlette/pull/2693).

## 0.38.5 (September 7, 2024)

#### Fixed

* Schedule `BackgroundTasks` from within `BaseHTTPMiddleware` [#2688](https://github.com/encode/starlette/pull/2688).
  This behavior was removed in 0.38.3, and is now restored.

## 0.38.4 (September 1, 2024)

#### Fixed

* Ensure accurate `root_path` removal in `get_route_path` function [#2600](https://github.com/encode/starlette/pull/2600).

## 0.38.3 (September 1, 2024)

#### Added

* Support for Python 3.13 [#2662](https://github.com/encode/starlette/pull/2662).

#### Fixed

* Don't poll for disconnects in `BaseHTTPMiddleware` via `StreamingResponse` [#2620](https://github.com/encode/starlette/pull/2620).

## 0.38.2 (July 27, 2024)

#### Fixed

* Not assume all routines have `__name__` on `routing.get_name()` [#2648](https://github.com/encode/starlette/pull/2648).

## 0.38.1 (July 23, 2024)

#### Removed

* Revert "Add support for ASGI pathsend extension" [#2649](https://github.com/encode/starlette/pull/2649).

## 0.38.0 (July 20, 2024)

#### Added

* Allow use of `memoryview` in `StreamingResponse` and `Response` [#2576](https://github.com/encode/starlette/pull/2576)
  and [#2577](https://github.com/encode/starlette/pull/2577).
* Send 404 instead of 500 when filename requested is too long on `StaticFiles` [#2583](https://github.com/encode/starlette/pull/2583).

#### Changed

* Fail fast on invalid `Jinja2Template` instantiation parameters [#2568](https://github.com/encode/starlette/pull/2568).
* Check endpoint handler is async only once [#2536](https://github.com/encode/starlette/pull/2536).

#### Fixed

* Add proper synchronization to `WebSocketTestSession` [#2597](https://github.com/encode/starlette/pull/2597).

## 0.37.2 (March 5, 2024)

#### Added

* Add `bytes` to `_RequestData` type [#2510](https://github.com/encode/starlette/pull/2510).

#### Fixed

* Revert "Turn `scope["client"]` to `None` on `TestClient` (#2377)" [#2525](https://github.com/encode/starlette/pull/2525).
* Remove deprecated `app` argument passed to `httpx.Client` on the `TestClient` [#2526](https://github.com/encode/starlette/pull/2526).

## 0.37.1 (February 9, 2024)

#### Fixed

* Warn instead of raise for missing env file on `Config` [#2485](https://github.com/encode/starlette/pull/2485).

## 0.37.0 (February 5, 2024)

#### Added

* Support the WebSocket Denial Response ASGI extension [#2041](https://github.com/encode/starlette/pull/2041).

## 0.36.3 (February 4, 2024)

#### Fixed

* Create `anyio.Event` on async context [#2459](https://github.com/encode/starlette/pull/2459).

## 0.36.2 (February 3, 2024)

#### Fixed

* Upgrade `python-multipart` to `0.0.7` [13e5c26](http://github.com/encode/starlette/commit/13e5c26a27f4903924624736abd6131b2da80cc5).
* Avoid duplicate charset on `Content-Type` [#2443](https://github.com/encode/starlette/2443).

## 0.36.1 (January 23, 2024)

#### Fixed

* Check if "extensions" in scope before checking the extension [#2438](http://github.com/encode/starlette/pull/2438).

## 0.36.0 (January 22, 2024)

#### Added

* Add support for ASGI `pathsend` extension [#2435](http://github.com/encode/starlette/pull/2435).
* Cancel `WebSocketTestSession` on close [#2427](http://github.com/encode/starlette/pull/2427).
* Raise `WebSocketDisconnect` when `WebSocket.send()` excepts `IOError` [#2425](http://github.com/encode/starlette/pull/2425).
* Raise `FileNotFoundError` when the `env_file` parameter on `Config` is not valid [#2422](http://github.com/encode/starlette/pull/2422).

## 0.35.1 (January 11, 2024)

#### Fixed

* Stop using the deprecated "method" parameter in `FileResponse` inside of `StaticFiles` [#2406](https://github.com/encode/starlette/pull/2406).
* Make `typing-extensions` optional again [#2409](https://github.com/encode/starlette/pull/2409).

## 0.35.0 (January 11, 2024)

#### Added

* Add `*args` to `Middleware` and improve its type hints [#2381](https://github.com/encode/starlette/pull/2381).

#### Fixed

* Use `Iterable` instead `Iterator` on `iterate_in_threadpool` [#2362](https://github.com/encode/starlette/pull/2362).

#### Changes

* Handle `root_path` to keep compatibility with mounted ASGI applications and WSGI [#2400](https://github.com/encode/starlette/pull/2400).
* Turn `scope["client"]` to `None` on `TestClient` [#2377](https://github.com/encode/starlette/pull/2377).

## 0.34.0 (December 16, 2023)

### Added

* Use `ParamSpec` for `run_in_threadpool` [#2375](https://github.com/encode/starlette/pull/2375).
* Add `UploadFile.__repr__` [#2360](https://github.com/encode/starlette/pull/2360).

### Fixed

* Merge URLs properly on `TestClient` [#2376](https://github.com/encode/starlette/pull/2376).
* Take weak ETags in consideration on `StaticFiles` [#2334](https://github.com/encode/starlette/pull/2334).

### Deprecated

* Deprecate `FileResponse(method=...)` parameter [#2366](https://github.com/encode/starlette/pull/2366).

## 0.33.0 (December 1, 2023)

### Added

* Add `middleware` per `Route`/`WebSocketRoute` [#2349](https://github.com/encode/starlette/pull/2349).
* Add `middleware` per `Router` [#2351](https://github.com/encode/starlette/pull/2351).

### Fixed

* Do not overwrite `"path"` and `"root_path"` scope keys [#2352](https://github.com/encode/starlette/pull/2352).
* Set `ensure_ascii=False` on `json.dumps()` for `WebSocket.send_json()` [#2341](https://github.com/encode/starlette/pull/2341).

## 0.32.0.post1 (November 5, 2023)

### Fixed

* Revert mkdocs-material from 9.1.17 to 9.4.7 [#2326](https://github.com/encode/starlette/pull/2326).

## 0.32.0 (November 4, 2023)

### Added

* Send `reason` on `WebSocketDisconnect` [#2309](https://github.com/encode/starlette/pull/2309).
* Add `domain` parameter to `SessionMiddleware` [#2280](https://github.com/encode/starlette/pull/2280).

### Changed

* Inherit from `HTMLResponse` instead of `Response` on `_TemplateResponse` [#2274](https://github.com/encode/starlette/pull/2274).
* Restore the `Response.render` type annotation to its pre-0.31.0 state [#2264](https://github.com/encode/starlette/pull/2264).

## 0.31.1 (August 26, 2023)

### Fixed

* Fix import error when `exceptiongroup` isn't available [#2231](https://github.com/encode/starlette/pull/2231).
* Set `url_for` global for custom Jinja environments [#2230](https://github.com/encode/starlette/pull/2230).

## 0.31.0 (July 24, 2023)

### Added

* Officially support Python 3.12 [#2214](https://github.com/encode/starlette/pull/2214).
* Support AnyIO 4.0 [#2211](https://github.com/encode/starlette/pull/2211).
* Strictly type annotate Starlette (strict mode on mypy) [#2180](https://github.com/encode/starlette/pull/2180).

### Fixed

* Don't group duplicated headers on a single string when using the `TestClient` [#2219](https://github.com/encode/starlette/pull/2219).

## 0.30.0 (July 13, 2023)

### Removed

* Drop Python 3.7 support [#2178](https://github.com/encode/starlette/pull/2178).

## 0.29.0 (July 13, 2023)

### Added

* Add `follow_redirects` parameter to `TestClient` [#2207](https://github.com/encode/starlette/pull/2207).
* Add `__str__` to `HTTPException` and `WebSocketException` [#2181](https://github.com/encode/starlette/pull/2181).
* Warn users when using `lifespan` together with `on_startup`/`on_shutdown` [#2193](https://github.com/encode/starlette/pull/2193).
* Collect routes from `Host` to generate the OpenAPI schema [#2183](https://github.com/encode/starlette/pull/2183).
* Add `request` argument to `TemplateResponse` [#2191](https://github.com/encode/starlette/pull/2191).

### Fixed

* Stop `body_stream` in case `more_body=False` on `BaseHTTPMiddleware` [#2194](https://github.com/encode/starlette/pull/2194).

## 0.28.0 (June 7, 2023)

### Changed
* Reuse `Request`'s body buffer for call_next in `BaseHTTPMiddleware` [#1692](https://github.com/encode/starlette/pull/1692).
* Move exception handling logic to `Route` [#2026](https://github.com/encode/starlette/pull/2026).

### Added
* Add `env` parameter to `Jinja2Templates`, and deprecate `**env_options` [#2159](https://github.com/encode/starlette/pull/2159).
* Add clear error message when `httpx` is not installed [#2177](https://github.com/encode/starlette/pull/2177).

### Fixed
* Allow "name" argument on `templates url_for()` [#2127](https://github.com/encode/starlette/pull/2127).

## 0.27.0 (May 16, 2023)

This release fixes a path traversal vulnerability in `StaticFiles`. You can view the full security advisory:
https://github.com/encode/starlette/security/advisories/GHSA-v5gw-mw7f-84px

### Added
* Minify JSON websocket data via `send_json` https://github.com/encode/starlette/pull/2128

### Fixed
* Replace `commonprefix` by `commonpath` on `StaticFiles` [1797de4](https://github.com/encode/starlette/commit/1797de464124b090f10cf570441e8292936d63e3).
* Convert ImportErrors into ModuleNotFoundError [#2135](https://github.com/encode/starlette/pull/2135).
* Correct the RuntimeError message content in websockets [#2141](https://github.com/encode/starlette/pull/2141).

## 0.26.1 (March 13, 2023)

### Fixed
* Fix typing of Lifespan to allow subclasses of Starlette [#2077](https://github.com/encode/starlette/pull/2077).

## 0.26.0.post1 (March 9, 2023)

### Fixed
* Replace reference from Events to Lifespan on the mkdocs.yml [#2072](https://github.com/encode/starlette/pull/2072).

## 0.26.0 (March 9, 2023)

### Added
* Support [lifespan state](lifespan.md) [#2060](https://github.com/encode/starlette/pull/2060),
  [#2065](https://github.com/encode/starlette/pull/2065) and [#2064](https://github.com/encode/starlette/pull/2064).

### Changed
* Change `url_for` signature to return a `URL` instance [#1385](https://github.com/encode/starlette/pull/1385).

### Fixed
* Allow "name" argument on `url_for()` and `url_path_for()` [#2050](https://github.com/encode/starlette/pull/2050).

### Deprecated
* Deprecate `on_startup` and `on_shutdown` events [#2070](https://github.com/encode/starlette/pull/2070).

## 0.25.0 (February 14, 2023)

### Fix
* Limit the number of fields and files when parsing `multipart/form-data` on the `MultipartParser` [8c74c2c](https://github.com/encode/starlette/commit/8c74c2c8dba7030154f8af18e016136bea1938fa) and [#2036](https://github.com/encode/starlette/pull/2036).

## 0.24.0 (February 6, 2023)

### Added
* Allow `StaticFiles` to follow symlinks [#1683](https://github.com/encode/starlette/pull/1683).
* Allow `Request.form()` as a context manager [#1903](https://github.com/encode/starlette/pull/1903).
* Add `size` attribute to `UploadFile` [#1405](https://github.com/encode/starlette/pull/1405).
* Add `env_prefix` argument to `Config` [#1990](https://github.com/encode/starlette/pull/1990).
* Add template context processors [#1904](https://github.com/encode/starlette/pull/1904).
* Support `str` and `datetime` on `expires` parameter on the `Response.set_cookie` method [#1908](https://github.com/encode/starlette/pull/1908).

### Changed
* Lazily build the middleware stack [#2017](https://github.com/encode/starlette/pull/2017).
* Make the `file` argument required on `UploadFile` [#1413](https://github.com/encode/starlette/pull/1413).
* Use debug extension instead of custom response template extension [#1991](https://github.com/encode/starlette/pull/1991).

### Fixed
* Fix url parsing of ipv6 urls on `URL.replace` [#1965](https://github.com/encode/starlette/pull/1965).

## 0.23.1 (December 9, 2022)

### Fixed
* Only stop receiving stream on `body_stream` if body is empty on the `BaseHTTPMiddleware` [#1940](https://github.com/encode/starlette/pull/1940).

## 0.23.0 (December 5, 2022)

### Added
* Add `headers` parameter to the `TestClient` [#1966](https://github.com/encode/starlette/pull/1966).

### Deprecated
* Deprecate `Starlette` and `Router` decorators [#1897](https://github.com/encode/starlette/pull/1897).

### Fixed
* Fix bug on `FloatConvertor` regex [#1973](https://github.com/encode/starlette/pull/1973).

## 0.22.0 (November 17, 2022)

### Changed
* Bypass `GZipMiddleware` when response includes `Content-Encoding` [#1901](https://github.com/encode/starlette/pull/1901).

### Fixed
* Remove unneeded `unquote()` from query parameters on the `TestClient` [#1953](https://github.com/encode/starlette/pull/1953).
* Make sure `MutableHeaders._list` is actually a `list` [#1917](https://github.com/encode/starlette/pull/1917).
* Import compatibility with the next version of `AnyIO` [#1936](https://github.com/encode/starlette/pull/1936).

## 0.21.0 (September 26, 2022)

This release replaces the underlying HTTP client used on the `TestClient` (`requests` :arrow_right: `httpx`), and as those clients [differ _a bit_ on their API](https://www.python-httpx.org/compatibility/), your test suite will likely break. To make the migration smoother, you can use the [`bump-testclient`](https://github.com/Kludex/bump-testclient) tool.

### Changed
* Replace `requests` with `httpx` in `TestClient` [#1376](https://github.com/encode/starlette/pull/1376).

### Added
* Add `WebSocketException` and support for WebSocket exception handlers [#1263](https://github.com/encode/starlette/pull/1263).
* Add `middleware` parameter to `Mount` class [#1649](https://github.com/encode/starlette/pull/1649).
* Officially support Python 3.11 [#1863](https://github.com/encode/starlette/pull/1863).
* Implement `__repr__` for route classes [#1864](https://github.com/encode/starlette/pull/1864).

### Fixed
* Fix bug on which `BackgroundTasks` were cancelled when using `BaseHTTPMiddleware` and client disconnected [#1715](https://github.com/encode/starlette/pull/1715).

## 0.20.4 (June 28, 2022)

### Fixed
* Remove converter from path when generating OpenAPI schema [#1648](https://github.com/encode/starlette/pull/1648).

## 0.20.3 (June 10, 2022)

### Fixed
* Revert "Allow `StaticFiles` to follow symlinks" [#1681](https://github.com/encode/starlette/pull/1681).

## 0.20.2 (June 7, 2022)

### Fixed
* Fix regression on route paths with colons [#1675](https://github.com/encode/starlette/pull/1675).
* Allow `StaticFiles` to follow symlinks [#1337](https://github.com/encode/starlette/pull/1377).

## 0.20.1 (May 28, 2022)

### Fixed
* Improve detection of async callables [#1444](https://github.com/encode/starlette/pull/1444).
* Send 400 (Bad Request) when `boundary` is missing [#1617](https://github.com/encode/starlette/pull/1617).
* Send 400 (Bad Request) when missing "name" field on `Content-Disposition` header [#1643](https://github.com/encode/starlette/pull/1643).
* Do not send empty data to `StreamingResponse` on `BaseHTTPMiddleware` [#1609](https://github.com/encode/starlette/pull/1609).
* Add `__bool__` dunder for `Secret` [#1625](https://github.com/encode/starlette/pull/1625).

## 0.20.0 (May 3, 2022)

### Removed
* Drop Python 3.6 support [#1357](https://github.com/encode/starlette/pull/1357) and [#1616](https://github.com/encode/starlette/pull/1616).


## 0.19.1 (April 22, 2022)

### Fixed
* Fix inference of `Route.name` when created from methods [#1553](https://github.com/encode/starlette/pull/1553).
* Avoid `TypeError` on `websocket.disconnect` when code is `None` [#1574](https://github.com/encode/starlette/pull/1574).

### Deprecated
* Deprecate `WS_1004_NO_STATUS_RCVD` and `WS_1005_ABNORMAL_CLOSURE` in favor of `WS_1005_NO_STATUS_RCVD` and `WS_1006_ABNORMAL_CLOSURE`, as the previous constants didn't match the [WebSockets specs](https://www.iana.org/assignments/websocket/websocket.xhtml) [#1580](https://github.com/encode/starlette/pull/1580).


## 0.19.0 (March 9, 2022)

### Added
* Error handler will always run, even if the error happens on a background task [#761](https://github.com/encode/starlette/pull/761).
* Add `headers` parameter to `HTTPException` [#1435](https://github.com/encode/starlette/pull/1435).
* Internal responses with `405` status code insert an `Allow` header, as described by [RFC 7231](https://datatracker.ietf.org/doc/html/rfc7231#section-6.5.5) [#1436](https://github.com/encode/starlette/pull/1436).
* The `content` argument in `JSONResponse` is now required [#1431](https://github.com/encode/starlette/pull/1431).
* Add custom URL convertor register [#1437](https://github.com/encode/starlette/pull/1437).
* Add content disposition type parameter to `FileResponse` [#1266](https://github.com/encode/starlette/pull/1266).
* Add next query param with original request URL in requires decorator [#920](https://github.com/encode/starlette/pull/920).
* Add `raw_path` to `TestClient` scope [#1445](https://github.com/encode/starlette/pull/1445).
* Add union operators to `MutableHeaders` [#1240](https://github.com/encode/starlette/pull/1240).
* Display missing route details on debug page [#1363](https://github.com/encode/starlette/pull/1363).
* Change `anyio` required version range to `>=3.4.0,<5.0` [#1421](https://github.com/encode/starlette/pull/1421) and [#1460](https://github.com/encode/starlette/pull/1460).
* Add `typing-extensions>=3.10` requirement - used only on lower versions than Python 3.10 [#1475](https://github.com/encode/starlette/pull/1475).

### Fixed
* Prevent `BaseHTTPMiddleware` from hiding errors of `StreamingResponse` and mounted applications [#1459](https://github.com/encode/starlette/pull/1459).
* `SessionMiddleware` uses an explicit `path=...`, instead of defaulting to the ASGI 'root_path' [#1512](https://github.com/encode/starlette/pull/1512).
* `Request.client` is now compliant with the ASGI specifications [#1462](https://github.com/encode/starlette/pull/1462).
* Raise `KeyError` at early stage for missing boundary [#1349](https://github.com/encode/starlette/pull/1349).

### Deprecated
* Deprecate WSGIMiddleware in favor of a2wsgi [#1504](https://github.com/encode/starlette/pull/1504).
* Deprecate `run_until_first_complete` [#1443](https://github.com/encode/starlette/pull/1443).


## 0.18.0 (January 23, 2022)

### Added
* Change default chunk size from 4Kb to 64Kb on `FileResponse` [#1345](https://github.com/encode/starlette/pull/1345).
* Add support for `functools.partial` in `WebSocketRoute` [#1356](https://github.com/encode/starlette/pull/1356).
* Add `StaticFiles` packages with directory [#1350](https://github.com/encode/starlette/pull/1350).
* Allow environment options in `Jinja2Templates` [#1401](https://github.com/encode/starlette/pull/1401).
* Allow HEAD method on `HttpEndpoint` [#1346](https://github.com/encode/starlette/pull/1346).
* Accept additional headers on `websocket.accept` message [#1361](https://github.com/encode/starlette/pull/1361) and [#1422](https://github.com/encode/starlette/pull/1422).
* Add `reason` to `WebSocket` close ASGI event [#1417](https://github.com/encode/starlette/pull/1417).
* Add headers attribute to `UploadFile` [#1382](https://github.com/encode/starlette/pull/1382).
* Don't omit `Content-Length` header for `Content-Length: 0` cases [#1395](https://github.com/encode/starlette/pull/1395).
* Don't set headers for responses with 1xx, 204 and 304 status code [#1397](https://github.com/encode/starlette/pull/1397).
* `SessionMiddleware.max_age` now accepts `None`, so cookie can last as long as the browser session [#1387](https://github.com/encode/starlette/pull/1387).

### Fixed
* Tweak `hashlib.md5()` function on `FileResponse`s ETag generation. The parameter [`usedforsecurity`](https://bugs.python.org/issue9216) flag is set to `False`, if the flag is available on the system. This fixes an error raised on systems with [FIPS](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/FIPS_Mode_-_an_explanation) enabled [#1366](https://github.com/encode/starlette/pull/1366) and [#1410](https://github.com/encode/starlette/pull/1410).
* Fix `path_params` type on `url_path_for()` method i.e. turn `str` into `Any` [#1341](https://github.com/encode/starlette/pull/1341).
* `Host` now ignores `port` on routing [#1322](https://github.com/encode/starlette/pull/1322).

## 0.17.1 (November 17, 2021)

### Fixed
* Fix `IndexError` in authentication `requires` when wrapped function arguments are distributed between `*args` and `**kwargs` [#1335](https://github.com/encode/starlette/pull/1335).

## 0.17.0 (November 4, 2021)

### Added
* `Response.delete_cookie` now accepts the same parameters as `Response.set_cookie` [#1228](https://github.com/encode/starlette/pull/1228).
* Update the `Jinja2Templates` constructor to allow `PathLike` [#1292](https://github.com/encode/starlette/pull/1292).

### Fixed
* Fix BadSignature exception handling in SessionMiddleware [#1264](https://github.com/encode/starlette/pull/1264).
* Change `HTTPConnection.__getitem__` return type from `str` to `typing.Any` [#1118](https://github.com/encode/starlette/pull/1118).
* Change `ImmutableMultiDict.getlist` return type from `typing.List[str]` to `typing.List[typing.Any]` [#1235](https://github.com/encode/starlette/pull/1235).
* Handle `OSError` exceptions on `StaticFiles` [#1220](https://github.com/encode/starlette/pull/1220).
* Fix `StaticFiles` 404.html in HTML mode [#1314](https://github.com/encode/starlette/pull/1314).
* Prevent anyio.ExceptionGroup in error views under a BaseHTTPMiddleware [#1262](https://github.com/encode/starlette/pull/1262).

### Removed
* Remove GraphQL support [#1198](https://github.com/encode/starlette/pull/1198).

## 0.16.0 (July 19, 2021)

### Added
 * Added [Encode](https://github.com/sponsors/encode) funding option
   [#1219](https://github.com/encode/starlette/pull/1219)

### Fixed
 * `starlette.websockets.WebSocket` instances are now hashable and compare by identity
    [#1039](https://github.com/encode/starlette/pull/1039)
 * A number of fixes related to running task groups in lifespan
   [#1213](https://github.com/encode/starlette/pull/1213),
   [#1227](https://github.com/encode/starlette/pull/1227)

### Deprecated/removed
 * The method `starlette.templates.Jinja2Templates.get_env` was removed
   [#1218](https://github.com/encode/starlette/pull/1218)
 * The ClassVar `starlette.testclient.TestClient.async_backend` was removed,
   the backend is now configured using constructor kwargs
   [#1211](https://github.com/encode/starlette/pull/1211)
 * Passing an Async Generator Function or a Generator Function to `starlette.routing.Router(lifespan=)` is deprecated. You should wrap your lifespan in `@contextlib.asynccontextmanager`.
   [#1227](https://github.com/encode/starlette/pull/1227)
   [#1110](https://github.com/encode/starlette/pull/1110)

## 0.15.0 (June 23, 2021)

This release includes major changes to the low-level asynchronous parts of Starlette. As a result,
**Starlette now depends on [AnyIO](https://anyio.readthedocs.io/en/stable/)** and some minor API
changes have occurred. Another significant change with this release is the
**deprecation of built-in GraphQL support**.

### Added
* Starlette now supports [Trio](https://trio.readthedocs.io/en/stable/) as an async runtime via
  AnyIO - [#1157](https://github.com/encode/starlette/pull/1157).
* `TestClient.websocket_connect()` now must be used as a context manager.
* Initial support for Python 3.10 - [#1201](https://github.com/encode/starlette/pull/1201).
* The compression level used in `GZipMiddleware` is now adjustable -
  [#1128](https://github.com/encode/starlette/pull/1128).

### Fixed
* Several fixes to `CORSMiddleware`. See [#1111](https://github.com/encode/starlette/pull/1111),
  [#1112](https://github.com/encode/starlette/pull/1112),
  [#1113](https://github.com/encode/starlette/pull/1113),
  [#1199](https://github.com/encode/starlette/pull/1199).
* Improved exception messages in the case of duplicated path parameter names -
  [#1177](https://github.com/encode/starlette/pull/1177).
* `RedirectResponse` now uses `quote` instead of `quote_plus` encoding for the `Location` header
  to better match the behaviour in other frameworks such as Django -
  [#1164](https://github.com/encode/starlette/pull/1164).
* Exception causes are now preserved in more cases -
  [#1158](https://github.com/encode/starlette/pull/1158).
* Session cookies now use the ASGI root path in the case of mounted applications -
  [#1147](https://github.com/encode/starlette/pull/1147).
* Fixed a cache invalidation bug when static files were deleted in certain circumstances -
  [#1023](https://github.com/encode/starlette/pull/1023).
* Improved memory usage of `BaseHTTPMiddleware` when handling large responses -
  [#1012](https://github.com/encode/starlette/issues/1012) fixed via #1157

### Deprecated/removed

* Built-in GraphQL support via the `GraphQLApp` class has been deprecated and will be removed in a
  future release. Please see [#619](https://github.com/encode/starlette/issues/619). GraphQL is not
  supported on Python 3.10.
* The `executor` parameter to `GraphQLApp` was removed. Use `executor_class` instead.
* The `workers` parameter to `WSGIMiddleware` was removed. This hasn't had any effect since
  Starlette v0.6.3.

## 0.14.2 (February 2, 2021)

### Fixed

* Fixed `ServerErrorMiddleware` compatibility with Python 3.9.1/3.8.7 when debug mode is enabled -
  [#1132](https://github.com/encode/starlette/pull/1132).
* Fixed unclosed socket `ResourceWarning`s when using the `TestClient` with WebSocket endpoints -
  #1132.
* Improved detection of `async` endpoints wrapped in `functools.partial` on Python 3.8+ -
  [#1106](https://github.com/encode/starlette/pull/1106).


## 0.14.1 (November 9th, 2020)

### Removed

* `UJSONResponse` was removed (this change was intended to be included in 0.14.0). Please see the
  [documentation](https://www.starlette.io/responses/#custom-json-serialization) for how to
  implement responses using custom JSON serialization -
  [#1074](https://github.com/encode/starlette/pull/1047).

## 0.14.0 (November 8th, 2020)

### Added

* Starlette now officially supports Python3.9.
* In `StreamingResponse`, allow custom async iterator such as objects from classes implementing `__aiter__`.
* Allow usage of `functools.partial` async handlers in Python versions 3.6 and 3.7.
* Add 418 I'm A Teapot status code.

### Changed

* Create tasks from handler coroutines before sending them to `asyncio.wait`.
* Use `format_exception` instead of `format_tb` in `ServerErrorMiddleware`'s `debug` responses.
* Be more lenient with handler arguments when using the `requires` decorator.

## 0.13.8

* Revert `Queue(maxsize=1)` fix for `BaseHTTPMiddleware` middleware classes and streaming responses.

* The `StaticFiles` constructor now allows `pathlib.Path` in addition to strings for its `directory` argument.

## 0.13.7

* Fix high memory usage when using `BaseHTTPMiddleware` middleware classes and streaming responses.

## 0.13.6

* Fix 404 errors with `StaticFiles`.

## 0.13.5

* Add support for `Starlette(lifespan=...)` functions.
* More robust path-traversal check in StaticFiles app.
* Fix WSGI PATH_INFO encoding.
* RedirectResponse now accepts optional background parameter
* Allow path routes to contain regex meta characters
* Treat ASGI HTTP 'body' as an optional key.
* Don't use thread pooling for writing to in-memory upload files.

## 0.13.0

* Switch to promoting application configuration on init style everywhere.
  This means dropping the decorator style in favour of declarative routing
  tables and middleware definitions.

## 0.12.12

* Fix `request.url_for()` for the Mount-within-a-Mount case.

## 0.12.11

* Fix `request.url_for()` when an ASGI `root_path` is being used.

## 0.12.1

* Add `URL.include_query_params(**kwargs)`
* Add `URL.replace_query_params(**kwargs)`
* Add `URL.remove_query_params(param_names)`
* `request.state` properly persisting across middleware.
* Added `request.scope` interface.

## 0.12.0

* Switch to ASGI 3.0.
* Fixes to CORS middleware.
* Add `StaticFiles(html=True)` support.
* Fix path quoting in redirect responses.

## 0.11.1

* Add `request.state` interface, for storing arbitrary additional information.
* Support disabling GraphiQL with `GraphQLApp(..., graphiql=False)`.

## 0.11.0

* `DatabaseMiddleware` is now dropped in favour of `databases`
* Templates are no longer configured on the application instance. Use `templates = Jinja2Templates(directory=...)` and `return templates.TemplateResponse('index.html', {"request": request})`
* Schema generation is no longer attached to the application instance. Use `schemas = SchemaGenerator(...)` and `return schemas.OpenAPIResponse(request=request)`
* `LifespanMiddleware` is dropped in favor of router-based lifespan handling.
* Application instances now accept a `routes` argument, `Starlette(routes=[...])`
* Schema generation now includes mounted routes.

## 0.10.6

* Add `Lifespan` routing component.

## 0.10.5

* Ensure `templating` does not strictly require `jinja2` to be installed.

## 0.10.4

* Templates are now configured independently from the application instance. `templates = Jinja2Templates(directory=...)`. Existing API remains in place, but is no longer documented,
and will be deprecated in due course. See the template documentation for more details.

## 0.10.3

* Move to independent `databases` package instead of `DatabaseMiddleware`. Existing API
remains in place, but is no longer documented, and will be deprecated in due course.

## 0.10.2

* Don't drop explicit port numbers on redirects from `HTTPSRedirectMiddleware`.

## 0.10.1

* Add MySQL database support.
* Add host-based routing.

## 0.10.0

* WebSockets now default to sending/receiving JSON over text data frames. Use `.send_json(data, mode="binary")` and `.receive_json(mode="binary")` for binary framing.
* `GraphQLApp` now takes an `executor_class` argument, which should be used in preference to the existing `executor` argument. Resolves an issue with async executors being instantiated before the event loop was setup. The `executor` argument is expected to be deprecated in the next median or major release.
* Authentication and the `@requires` decorator now support WebSocket endpoints.
* `MultiDict` and `ImmutableMultiDict` classes are available in `uvicorn.datastructures`.
* `QueryParams` is now instantiated with standard dict-style `*args, **kwargs` arguments.

## 0.9.11

* Session cookies now include browser 'expires', in addition to the existing signed expiry.
* `request.form()` now returns a multi-dict interface.
* The query parameter multi-dict implementation now mirrors `dict` more correctly for the
behavior of `.keys()`, `.values()`, and `.items()` when multiple same-key items occur.
* Use `urlsplit` throughout in favor of `urlparse`.

## 0.9.10

* Support `@requires(...)` on class methods.
* Apply URL escaping to form data.
* Support `HEAD` requests automatically.
* Add `await request.is_disconnected()`.
* Pass operationName to GraphQL executor.

## 0.9.9

* Add `TemplateResponse`.
* Add `CommaSeparatedStrings` datatype.
* Add `BackgroundTasks` for multiple tasks.
* Common subclass for `Request` and `WebSocket`, to eg. share `session` functionality.
* Expose remote address with `request.client`.

## 0.9.8

* Add `request.database.executemany`.

## 0.9.7

* Ensure that `AuthenticationMiddleware` handles lifespan messages correctly.

## 0.9.6

* Add `AuthenticationMiddleware`, and `@requires()` decorator.

## 0.9.5

* Support either `str` or `Secret` for `SessionMiddleware(secret_key=...)`.

## 0.9.4

* Add `config.environ`.
* Add `datastructures.Secret`.
* Add `datastructures.DatabaseURL`.

## 0.9.3

* Add `config.Config(".env")`

## 0.9.2

* Add optional database support.
* Add `request` to GraphQL context.
* Hide any password component in `URL.__repr__`.

## 0.9.1

* Handle startup/shutdown errors properly.

## 0.9.0

* `TestClient` can now be used as a context manager, instead of `LifespanContext`.
* Lifespan is now handled as middleware. Startup and Shutdown events are
visible throughout the middleware stack.

## 0.8.8

* Better support for third-party API schema generators.

## 0.8.7

* Support chunked requests with TestClient.
* Cleanup asyncio tasks properly with WSGIMiddleware.
* Support using TestClient within endpoints, for service mocking.

## 0.8.6

* Session cookies are now set on the root path.

## 0.8.5

* Support URL convertors.
* Support HTTP 304 cache responses from `StaticFiles`.
* Resolve character escaping issue with form data.

## 0.8.4

* Default to empty body on responses.

## 0.8.3

* Add 'name' argument to `@app.route()`.
* Use 'Host' header for URL reconstruction.

## 0.8.2

### StaticFiles

* StaticFiles no longer reads the file for responses to `HEAD` requests.

## 0.8.1

### Templating

* Add a default templating configuration with Jinja2.

Allows the following:

```python
app = Starlette(template_directory="templates")

@app.route('/')
async def homepage(request):
    # `url_for` is available inside the template.
    template = app.get_template('index.html')
    content = template.render(request=request)
    return HTMLResponse(content)
```

## 0.8.0

### Exceptions

* Add support for `@app.exception_handler(404)`.
* Ensure handled exceptions are not seen as errors by the middleware stack.

### SessionMiddleware

* Add `max_age`, and use timestamp-signed cookies. Defaults to two weeks.

### Cookies

* Ensure cookies are strictly HTTP correct.

### StaticFiles

* Check directory exists on instantiation.

## 0.7.4

### Concurrency

* Add `starlette.concurrency.run_in_threadpool`. Now handles `contextvar` support.

## 0.7.3

### Routing

* Add `name=` support to `app.mount()`. This allows eg: `app.mount('/static', StaticFiles(directory='static'), name='static')`.

## 0.7.2

### Middleware

* Add support for `@app.middleware("http")` decorator.

### Routing

* Add "endpoint" to ASGI scope.

## 0.7.1

### Debug tracebacks

* Improve debug traceback information & styling.

### URL routing

* Support mounted URL lookups with "path=", eg. `url_for('static', path=...)`.
* Support nested URL lookups, eg. `url_for('admin:user', username=...)`.
* Add redirect slashes support.
* Add www redirect support.

### Background tasks

* Add background task support to `FileResponse` and `StreamingResponse`.

## 0.7.0

### API Schema support

* Add `app.schema_generator = SchemaGenerator(...)`.
* Add `app.schema` property.
* Add `OpenAPIResponse(...)`.

### GraphQL routing

* Drop `app.add_graphql_route("/", ...)` in favor of more consistent `app.add_route("/", GraphQLApp(...))`.

## 0.6.3

### Routing API

* Support routing to methods.
* Ensure `url_path_for` works with Mount('/{some_path_params}').
* Fix Router(default=) argument.
* Support repeated paths, like: `@app.route("/", methods=["GET"])`, `@app.route("/", methods=["POST"])`
* Use the default ThreadPoolExecutor for all sync endpoints.

## 0.6.2

### SessionMiddleware

Added support for `request.session`, with `SessionMiddleware`.

## 0.6.1

### BaseHTTPMiddleware

Added support for `BaseHTTPMiddleware`, which provides a standard
request/response interface over a regular ASGI middleware.

This means you can write ASGI middleware while still working at
a request/response level, rather than handling ASGI messages directly.

```python
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware


class CustomMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers['Custom-Header'] = 'Example'
        return response


app = Starlette()
app.add_middleware(CustomMiddleware)
```

## 0.6.0

### request.path_params

The biggest change in 0.6 is that endpoint signatures are no longer:

```python
async def func(request: Request, **kwargs) -> Response
```

Instead we just use:

```python
async def func(request: Request) -> Response
```

The path parameters are available on the request as `request.path_params`.

This is different to most Python webframeworks, but I think it actually ends up
being much more nicely consistent all the way through.

### request.url_for()

Request and WebSocketSession now support URL reversing with `request.url_for(name, **path_params)`.
This method returns a fully qualified `URL` instance.
The URL instance is a string-like object.

### app.url_path_for()

Applications now support URL path reversing with `app.url_path_for(name, **path_params)`.
This method returns a `URL` instance with the path and scheme set.
The URL instance is a string-like object, and will return only the path if coerced to a string.

### app.routes

Applications now support a `.routes` parameter, which returns a list of `[Route|WebSocketRoute|Mount]`.

### Route, WebSocketRoute, Mount

The low level components to `Router` now match the `@app.route()`, `@app.websocket_route()`, and `app.mount()` signatures.
