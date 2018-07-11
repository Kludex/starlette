_begin_form = "begin_form"
_begin_file = "begin_file"
_cont = "cont"
_end = "end"


class MultiPartParser(object):
    def __init__(
        self,
        stream_factory=None,
        charset="utf-8",
        errors="replace",
        max_form_memory_size=None,
        cls=None,
        buffer_size=64 * 1024,
    ):
        self.charset = charset
        self.errors = errors
        self.max_form_memory_size = max_form_memory_size
        self.stream_factory = (
            default_stream_factory if stream_factory is None else stream_factory
        )
        self.cls = MultiDict if cls is None else cls

        # make sure the buffer size is divisible by four so that we can base64
        # decode chunk by chunk
        assert buffer_size % 4 == 0, "buffer size has to be divisible by 4"
        # also the buffer size has to be at least 1024 bytes long or long headers
        # will freak out the system
        assert buffer_size >= 1024, "buffer size has to be at least 1KB"

        self.buffer_size = buffer_size

    def _fix_ie_filename(self, filename):
        """Internet Explorer 6 transmits the full file name if a file is
        uploaded.  This function strips the full path if it thinks the
        filename is Windows-like absolute.
        """
        if filename[1:3] == ":\\" or filename[:2] == "\\\\":
            return filename.split("\\")[-1]
        return filename

    def _find_terminator(self, iterator):
        """The terminator might have some additional newlines before it.
        There is at least one application that sends additional newlines
        before headers (the python setuptools package).
        """
        for line in iterator:
            if not line:
                break
            line = line.strip()
            if line:
                return line
        return b""

    def fail(self, message):
        raise ValueError(message)

    def get_part_encoding(self, headers):
        transfer_encoding = headers.get("content-transfer-encoding")
        if (
            transfer_encoding is not None
            and transfer_encoding in _supported_multipart_encodings
        ):
            return transfer_encoding

    def get_part_charset(self, headers):
        # Figure out input charset for current part
        content_type = headers.get("content-type")
        if content_type:
            mimetype, ct_params = parse_options_header(content_type)
            return ct_params.get("charset", self.charset)
        return self.charset

    def start_file_streaming(self, filename, headers, total_content_length):
        if isinstance(filename, bytes):
            filename = filename.decode(self.charset, self.errors)
        filename = self._fix_ie_filename(filename)
        content_type = headers.get("content-type")
        try:
            content_length = int(headers["content-length"])
        except (KeyError, ValueError):
            content_length = 0
        container = self.stream_factory(
            total_content_length, content_type, filename, content_length
        )
        return filename, container

    def in_memory_threshold_reached(self, bytes):
        raise exceptions.RequestEntityTooLarge()

    def validate_boundary(self, boundary):
        if not boundary:
            self.fail("Missing boundary")
        if not is_valid_multipart_boundary(boundary):
            self.fail("Invalid boundary: %s" % boundary)
        if len(boundary) > self.buffer_size:  # pragma: no cover
            # this should never happen because we check for a minimum size
            # of 1024 and boundaries may not be longer than 200.  The only
            # situation when this happens is for non debug builds where
            # the assert is skipped.
            self.fail("Boundary longer than buffer size")

    class LineSplitter(object):
        def __init__(self, cap=None):
            self.buffer = b""
            self.cap = cap

        def _splitlines(self, pre, post):
            buf = pre + post
            rv = []
            if not buf:
                return rv, b""
            lines = buf.splitlines(True)
            iv = b""
            for line in lines:
                iv += line
                while self.cap and len(iv) >= self.cap:
                    rv.append(iv[: self.cap])
                    iv = iv[self.cap :]
                if line[-1:] in b"\r\n":
                    rv.append(iv)
                    iv = b""
            # If this isn't the very end of the stream and what we got ends
            # with \r, we need to hold on to it in case an \n comes next
            if post and rv and not iv and rv[-1][-1:] == b"\r":
                iv = rv[-1]
                del rv[-1]
            return rv, iv

        def feed(self, data):
            lines, self.buffer = self._splitlines(self.buffer, data)
            if not data:
                lines += [self.buffer]
                if self.buffer:
                    lines += [b""]
            return lines

    class LineParser(object):
        def __init__(self, parent, boundary):
            self.parent = parent
            self.boundary = boundary
            self._next_part = b"--" + boundary
            self._last_part = self._next_part + b"--"
            self._state = self._state_pre_term
            self._output = []
            self._headers = []
            self._tail = b""
            self._codec = None

        def _start_content(self):
            disposition = self._headers.get("content-disposition")
            if disposition is None:
                raise ValueError("Missing Content-Disposition header")
            self.disposition, extra = parse_options_header(disposition)
            transfer_encoding = self.parent.get_part_encoding(self._headers)
            if transfer_encoding is not None:
                if transfer_encoding == "base64":
                    transfer_encoding = "base64_codec"
                try:
                    self._codec = codecs.lookup(transfer_encoding)
                except Exception:
                    raise ValueError(
                        "Cannot decode transfer-encoding: %r" % transfer_encoding
                    )
            self.name = extra.get("name")
            self.filename = extra.get("filename")
            if self.filename is not None:
                self._output.append(
                    ("begin_file", (self._headers, self.name, self.filename))
                )
            else:
                self._output.append(("begin_form", (self._headers, self.name)))
            return self._state_output

        def _state_done(self, line):
            return self._state_done

        def _state_output(self, line):
            if not line:
                raise ValueError("Unexpected end of file")
            sline = line.rstrip()
            if sline == self._last_part:
                self._tail = b""
                self._output.append(("end", None))
                return self._state_done
            elif sline == self._next_part:
                self._tail = b""
                self._output.append(("end", None))
                self._headers = []
                return self._state_headers

            if self._codec:
                try:
                    line, _ = self._codec.decode(line)
                except Exception:
                    raise ValueError("Could not decode transfer-encoded chunk")

            # We don't know yet whether we can output the final newline, so
            # we'll save it in self._tail and output it next time.
            tail = self._tail
            if line[-2:] == b"\r\n":
                self._output.append(("cont", tail + line[:-2]))
                self._tail = line[-2:]
            elif line[-1:] in b"\r\n":
                self._output.append(("cont", tail + line[:-1]))
                self._tail = line[-1:]
            else:
                self._output.append(("cont", tail + line))
                self._tail = b""
            return self._state_output

        def _state_pre_term(self, line):
            if not line:
                raise ValueError("Unexpected end of file")
                return self._state_pre_term
            line = line.rstrip(b"\r\n")
            if not line:
                return self._state_pre_term
            if line == self._last_part:
                return self._state_done
            elif line == self._next_part:
                self._headers = []
                return self._state_headers
            raise ValueError("Expected boundary at start of multipart data")

        def _state_headers(self, line):
            if line is None:
                raise ValueError("Unexpected end of file during headers")
            line = to_native(line)
            line, line_terminated = _line_parse(line)
            if not line_terminated:
                raise ValueError("Unexpected end of line in multipart header")
            if not line:
                self._headers = Headers(self._headers)
                return self._start_content()
            if line[0] in " \t" and self._headers:
                key, value = self._headers[-1]
                self._headers[-1] = (key, value + "\n " + line[1:])
            else:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    self._headers.append((parts[0].strip(), parts[1].strip()))
                else:
                    raise ValueError("Malformed header")
            return self._state_headers

        def feed(self, lines):
            self._output = []
            s = self._state
            for line in lines:
                s = s(line)
            self._state = s
            return self._output

    class PartParser(object):
        def __init__(self, parent, content_length):
            self.parent = parent
            self.content_length = content_length
            self._write = None
            self._in_memory = 0
            self._guard_memory = False

        def _feed_one(self, event):
            ev, data = event
            p = self.parent
            if ev == "begin_file":
                self._headers, self._name, filename = data
                self._filename, self._container = p.start_file_streaming(
                    filename, self._headers, self.content_length
                )
                self._write = self._container.write
                self._is_file = True
                self._guard_memory = False
            elif ev == "begin_form":
                self._headers, self._name = data
                self._container = []
                self._write = self._container.append
                self._is_file = False
                self._guard_memory = p.max_form_memory_size is not None
            elif ev == "cont":
                self._write(data)
                if self._guard_memory:
                    self._in_memory += len(data)
                    if self._in_memory > p.max_form_memory_size:
                        p.in_memory_threshold_reached(self._in_memory)
            elif ev == "end":
                if self._is_file:
                    self._container.seek(0)
                    return (
                        "file",
                        (
                            self._name,
                            FileStorage(
                                self._container,
                                self._filename,
                                self._name,
                                headers=self._headers,
                            ),
                        ),
                    )
                else:
                    part_charset = p.get_part_charset(self._headers)
                    return (
                        "form",
                        (
                            self._name,
                            b"".join(self._container).decode(part_charset, p.errors),
                        ),
                    )

        def feed(self, events):
            rv = []
            for event in events:
                v = self._feed_one(event)
                if v is not None:
                    rv.append(v)
            return rv

    def parse_lines(self, file, boundary, content_length, cap_at_buffer=True):
        """Generate parts of
        ``('begin_form', (headers, name))``
        ``('begin_file', (headers, name, filename))``
        ``('cont', bytestring)``
        ``('end', None)``
        Always obeys the grammar
        parts = ( begin_form cont* end |
                  begin_file cont* end )*
        """

        line_splitter = self.LineSplitter(self.buffer_size if cap_at_buffer else None)
        line_parser = self.LineParser(self, boundary)
        while True:
            buf = file.read(self.buffer_size)
            lines = line_splitter.feed(buf)
            parts = line_parser.feed(lines)
            for part in parts:
                yield part
            if buf == b"":
                break

    def parse_parts(self, file, boundary, content_length):
        """Generate ``('file', (name, val))`` and
        ``('form', (name, val))`` parts.
        """
        line_splitter = self.LineSplitter()
        line_parser = self.LineParser(self, boundary)
        part_parser = self.PartParser(self, content_length)
        while True:
            buf = file.read(self.buffer_size)
            lines = line_splitter.feed(buf)
            parts = line_parser.feed(lines)
            events = part_parser.feed(parts)
            for event in events:
                yield event
            if buf == b"":
                break

    def parse(self, file, boundary, content_length):
        formstream, filestream = tee(
            self.parse_parts(file, boundary, content_length), 2
        )
        form = (p[1] for p in formstream if p[0] == "form")
        files = (p[1] for p in filestream if p[0] == "file")
        return self.cls(form), self.cls(files)
