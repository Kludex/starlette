"""
WebTransport connection handling.

This module provides WebTransport support for Starlette, aligning with the
developer-friendly API design.
"""
from __future__ import annotations

import enum
import asyncio
from typing import AsyncIterator, Dict, Optional, List

from starlette.requests import HTTPConnection
from starlette.types import Message, Receive, Scope, Send


class WebTransportState(enum.Enum):
    """State of a WebTransport connection."""
    CONNECTING = 0
    CONNECTED = 1
    DISCONNECTED = 2


class WebTransportDisconnect(Exception):
    """Raised when a WebTransport connection is disconnected."""
    
    def __init__(self, code: int = 0, reason: str | None = None) -> None:
        self.code = code
        self.reason = reason or ""


class WebTransportStream:
    """Represents a single reliable stream within the session."""
    
    def __init__(self, transport: "WebTransport", stream_id: int) -> None:
        self._transport = transport
        self._stream_id = stream_id
        self._receive_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._read_closed = False
        self._write_closed = False

    @property
    def stream_id(self) -> int:
        return self._stream_id

    async def receive_bytes(self) -> bytes:
        """Reads data from the stream."""
        if self._read_closed and self._receive_queue.empty():
             raise WebTransportDisconnect(0, "Stream closed")
             
        try:
            data = await self._receive_queue.get()
            if data is None: # Sentinel for closed
                self._read_closed = True
                raise WebTransportDisconnect(0, "Stream closed")
            return data
        except RuntimeError:
            # Queue might be closed
             raise WebTransportDisconnect(0, "Connection closed")

    async def send_bytes(self, data: bytes) -> None:
        """Writes data to the stream."""
        if self._write_closed:
            raise RuntimeError("Stream is closed for writing")
        
        # We assume sending doesn't close the stream automatically unless specifically requested?
        # The design doc says "close() -> Closes this specific stream".
        # So send_bytes just sends.
        await self._transport._send_stream_data(self._stream_id, data, finish=False)

    async def close(self) -> None:
        """Closes this specific stream without closing the session."""
        self._write_closed = True
        # Send a FIN with empty data
        await self._transport._send_stream_data(self._stream_id, b"", finish=True)


class WebTransport(HTTPConnection):
    """
    Represents a WebTransport connection.
    
    Handles the session handshake and acts as a factory/manager for 
    streams and datagrams.
    """
    
    def __init__(self, scope: Scope, receive: Receive, send: Send) -> None:
        super().__init__(scope)
        assert scope["type"] == "webtransport"
        self._receive = receive
        self._send = send
        self.client_state = WebTransportState.CONNECTING
        self.application_state = WebTransportState.CONNECTING
        
        # Multiplexing structures
        self._streams: Dict[int, WebTransportStream] = {}
        self._accepted_streams_queue: asyncio.Queue[WebTransportStream] = asyncio.Queue()
        self._datagram_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._reader_task: Optional[asyncio.Task] = None

    async def accept(self) -> None:
        """Accepts the WebTransport session."""
        if self.application_state != WebTransportState.CONNECTING:
            raise RuntimeError('Cannot accept connection in %s state' % self.application_state)

        await self._send({"type": "webtransport.accept"})
        self.application_state = WebTransportState.CONNECTED
        self.client_state = WebTransportState.CONNECTED
        
        # Start background reader for multiplexing
        self._reader_task = asyncio.create_task(self._reader_loop())

    async def close(self, code: int = 0, reason: str = "") -> None:
        """Closes the session."""
        if self.application_state == WebTransportState.DISCONNECTED:
            return
            
        self.application_state = WebTransportState.DISCONNECTED
        await self._send({
            "type": "webtransport.close",
            "code": code,
            "reason": reason
        })
        
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass

    async def send_datagram(self, data: bytes) -> None:
        """Sends a raw datagram."""
        if self.application_state != WebTransportState.CONNECTED:
            raise RuntimeError("Connection is not connected")
        await self._send({
            "type": "webtransport.datagram.send",
            "data": data
        })

    async def receive_datagram(self) -> bytes:
        """Waits for and returns the next datagram."""
        if self.client_state == WebTransportState.DISCONNECTED and self._datagram_queue.empty():
             raise WebTransportDisconnect()
             
        data = await self._datagram_queue.get()
        if data is None:
            raise WebTransportDisconnect()
        return data

    async def iter_datagrams(self) -> AsyncIterator[bytes]:
        """Async iterator for incoming datagrams."""
        try:
            while True:
                yield await self.receive_datagram()
        except WebTransportDisconnect:
            pass

    async def accept_stream(self) -> WebTransportStream:
        """Waits for the client to open a stream."""
        if self.client_state == WebTransportState.DISCONNECTED and self._accepted_streams_queue.empty():
             raise WebTransportDisconnect()
             
        stream = await self._accepted_streams_queue.get()
        if stream is None:
            raise WebTransportDisconnect()
        return stream

    async def create_bidirectional_stream(self) -> WebTransportStream:
        """Initiates a new bidirectional stream to the client."""
        # TODO: Need protocol support to allocate Stream IDs from server side
        raise NotImplementedError("Server-initiated bidirectional streams are not yet supported")

    async def create_unidirectional_stream(self) -> WebTransportStream:
        """Initiates a new unidirectional stream to the client."""
        raise NotImplementedError("Server-initiated unidirectional streams are not yet supported")

    # API Internal Methods
    
    async def _send_stream_data(self, stream_id: int, data: bytes, finish: bool) -> None:
        if self.application_state != WebTransportState.CONNECTED:
            raise RuntimeError("Connection is not connected")
            
        await self._send({
            "type": "webtransport.stream.send",
            "stream_id": stream_id,
            "data": data,
            "finish": finish
        })

    async def _reader_loop(self) -> None:
        """Background task to read from ASGI receive and demultiplex."""
        try:
            while True:
                message = await self._receive()
                print(f"DEBUG: WebTransport reader received: {message['type']}")
                msg_type = message["type"]
                
                if msg_type == "webtransport.datagram.receive":
                    self._datagram_queue.put_nowait(message["data"])
                    
                elif msg_type == "webtransport.stream.receive":
                    stream_id = message["stream_id"]
                    data = message["data"]
                    more_body = message.get("more_body", True)
                    print(f"DEBUG: Reader stream {stream_id} data len={len(data)} more_body={more_body}")
                    
                    if stream_id not in self._streams:
                        # New stream!
                        stream = WebTransportStream(self, stream_id)
                        self._streams[stream_id] = stream
                        self._accepted_streams_queue.put_nowait(stream)
                    
                    stream = self._streams[stream_id]
                    stream._receive_queue.put_nowait(data)
                    
                    if not more_body:
                        # Stream ended
                        stream._receive_queue.put_nowait(None) # Sentinel
                        
                elif msg_type == "webtransport.disconnect":
                    self.client_state = WebTransportState.DISCONNECTED
                    self._cleanup_queues()
                    break
                    
        except Exception:
            self.client_state = WebTransportState.DISCONNECTED
            self._cleanup_queues()
            
    def _cleanup_queues(self):
        """Unblock all waiters with sentinels."""
        self._datagram_queue.put_nowait(None)
        self._accepted_streams_queue.put_nowait(None)
        for stream in self._streams.values():
            stream._receive_queue.put_nowait(None)


class WebTransportClose:
    """ASGI application that closes a WebTransport connection."""
    
    def __init__(self, code: int = 0, reason: str | None = None) -> None:
        self.code = code
        self.reason = reason or ""

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "webtransport.close", "code": self.code, "reason": self.reason})
