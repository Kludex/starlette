
Starlette includes a `Request` class that gives you a nicer interface onto
the incoming request, rather than accessing the ASGI scope and receive channel directly.

### Request

Signature: `Request(scope, receive=None)`

```python
from starlette.requests import Request
from starlette.responses import Response


async def app(scope, receive, send):
    assert scope['type'] == 'http'
    request = Request(scope, receive)
    content = '%s %s' % (request.method, request.url.path)
    response = Response(content, media_type='text/plain')
    await response(scope, receive, send)
```

Requests present a mapping interface, so you can use them in the same
way as a `scope`.

For instance: `request['path']` will return the ASGI path.

If you don't need to access the request body you can instantiate a request
without providing an argument to `receive`.

#### Method

The request method is accessed as `request.method`.

#### URL

The request URL is accessed as `request.url`.

The property is a string-like object that exposes all the
components that can be parsed out of the URL.

For example: `request.url.path`, `request.url.port`, `request.url.scheme`.

#### Headers

Headers are exposed as an immutable, case-insensitive, multi-dict.

For example: `request.headers['content-type']`

#### Query Parameters

Query parameters are exposed as an immutable multi-dict.

For example: `request.query_params['search']`

#### Path Parameters

Router path parameters are exposed as a dictionary interface.

For example: `request.path_params['username']`

#### Client Address

The client's remote address is exposed as a named two-tuple `request.client` (or `None`).

The hostname or IP address: `request.client.host`

The port number from which the client is connecting: `request.client.port`

#### Cookies

Cookies are exposed as a regular dictionary interface.

For example: `request.cookies.get('mycookie')`

Cookies are ignored in case of an invalid cookie. (RFC2109)

#### Body

There are a few different interfaces for returning the body of the request:

The request body as bytes: `await request.body()`

The request body, parsed as form data or multipart: `async with request.form() as form:`

The request body, parsed as JSON: `await request.json()`

You can also access the request body as a stream, using the `async for` syntax:

```python
from starlette.requests import Request
from starlette.responses import Response

    
async def app(scope, receive, send):
    assert scope['type'] == 'http'
    request = Request(scope, receive)
    body = b''
    async for chunk in request.stream():
        body += chunk
    response = Response(body, media_type='text/plain')
    await response(scope, receive, send)
```

If you access `.stream()` then the byte chunks are provided without storing
the entire body to memory. Any subsequent calls to `.body()`, `.form()`, or `.json()`
will raise an error.

In some cases such as long-polling, or streaming responses you might need to
determine if the client has dropped the connection. You can determine this
state with `disconnected = await request.is_disconnected()`.

#### Request Files

Request files are normally sent as multipart form data (`multipart/form-data`).

Signature: `request.form(max_files=1000, max_fields=1000, max_part_size=1024*1024)`

You can configure the number of maximum fields or files with the parameters `max_files` and `max_fields`; and part size using `max_part_size`:

```python
async with request.form(max_files=1000, max_fields=1000, max_part_size=1024*1024):
    ...
```

!!! info
    These limits are for security reasons, allowing an unlimited number of fields or files could lead to a denial of service attack by consuming a lot of CPU and memory parsing too many empty fields.

When you call `async with request.form() as form` you receive a `starlette.datastructures.FormData` which is an immutable
multidict, containing both file uploads and text input. File upload items are represented as instances of `starlette.datastructures.UploadFile`.

`UploadFile` has the following attributes:

* `filename`: An `str` with the original file name that was uploaded or `None` if its not available (e.g. `myimage.jpg`).
* `content_type`: An `str` with the content type (MIME type / media type) or `None` if it's not available (e.g. `image/jpeg`).
* `file`: A <a href="https://docs.python.org/3/library/tempfile.html#tempfile.SpooledTemporaryFile" target="_blank">`SpooledTemporaryFile`</a> (a <a href="https://docs.python.org/3/glossary.html#term-file-like-object" target="_blank">file-like</a> object). This is the actual Python file that you can pass directly to other functions or libraries that expect a "file-like" object.
* `headers`: A `Headers` object. Often this will only be the `Content-Type` header, but if additional headers were included in the multipart field they will be included here. Note that these headers have no relationship with the headers in `Request.headers`.
* `size`: An `int` with uploaded file's size in bytes. This value is calculated from request's contents, making it better choice to find uploaded file's size than `Content-Length` header. `None` if not set.

`UploadFile` has the following `async` methods. They all call the corresponding file methods underneath (using the internal `SpooledTemporaryFile`).

* `async write(data)`: Writes `data` (`bytes`) to the file.
* `async read(size)`: Reads `size` (`int`) bytes of the file.
* `async seek(offset)`: Goes to the byte position `offset` (`int`) in the file.
    * E.g., `await myfile.seek(0)` would go to the start of the file.
* `async close()`: Closes the file.

As all these methods are `async` methods, you need to "await" them.

For example, you can get the file name and the contents with:

```python
async with request.form() as form:
    filename = form["upload_file"].filename
    contents = await form["upload_file"].read()
```

!!! info
    As settled in [RFC-7578: 4.2](https://www.ietf.org/rfc/rfc7578.txt), form-data content part that contains file 
    assumed to have `name` and `filename` fields in `Content-Disposition` header: `Content-Disposition: form-data;
    name="user"; filename="somefile"`. Though `filename` field is optional according to RFC-7578, it helps 
    Starlette to differentiate which data should be treated as file. If `filename` field was supplied, `UploadFile` 
    object will be created to access underlying file, otherwise form-data part will be parsed and available as a raw 
    string.

#### Application

The originating Starlette application can be accessed via `request.app`.

#### Other state

If you want to store additional information on the request you can do so
using `request.state`.

For example:

`request.state.time_started = time.time()`
