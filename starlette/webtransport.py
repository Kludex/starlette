"""
WebTransport connection handling.

This module provides WebTransport support for ASGI applications, similar to
how websockets.py provides WebSocket support.
"""
from __future__ import annotations

import enum
from collections.abc import Iterable
from typing import Any

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


class WebTransport(HTTPConnection):
    """Represents a WebTransport connection.
    
    Provides methods for accepting connections, sending/receiving data
    on streams, and sending/receiving datagrams.
    """
    
    def __init__(self, scope: Scope, receive: Receive, send: Send) -> None:
        super().__init__(scope)
        assert scope["type"] == "webtransport"
        self._receive = receive
        self._send = send
        self.client_state = WebTransportState.CONNECTING
        self.application_state = WebTransportState.CONNECTING

    @property
    def session_id(self) -> int:
        """Get the WebTransport session ID."""
        return self.scope.get("extensions", {}).get("webtransport", {}).get("session_id", 0)

    async def receive(self) -> Message:
        """Receive ASGI WebTransport messages, ensuring valid state transitions."""
        if self.client_state == WebTransportState.CONNECTING:
            message = await self._receive()
            message_type = message["type"]
            if message_type == "webtransport.connect":
                self.client_state = WebTransportState.CONNECTED
            return message
            
        elif self.client_state == WebTransportState.CONNECTED:
            message = await self._receive()
            message_type = message["type"]
            if message_type == "webtransport.disconnect":
                self.client_state = WebTransportState.DISCONNECTED
            return message
            
        else:
            raise RuntimeError(
                'Cannot receive on a WebTransport connection in the "%s" state.'
                % self.client_state.name
            )

    async def send(self, message: Message) -> None:
        """Send ASGI WebTransport messages, ensuring valid state transitions."""
        if self.application_state == WebTransportState.CONNECTING:
            message_type = message["type"]
            if message_type == "webtransport.accept":
                self.application_state = WebTransportState.CONNECTED
            elif message_type == "webtransport.close":
                self.application_state = WebTransportState.DISCONNECTED
            else:
                raise RuntimeError(
                    f'Cannot send "{message_type}" while connecting. '
                    'Call accept() or close() first.'
                )
            await self._send(message)
            
        elif self.application_state == WebTransportState.CONNECTED:
            message_type = message["type"]
            if message_type == "webtransport.close":
                self.application_state = WebTransportState.DISCONNECTED
            await self._send(message)
            
        else:
            raise RuntimeError(
                'Cannot send on a WebTransport connection in the "%s" state.'
                % self.application_state.name
            )

    async def accept(
        self,
        headers: Iterable[tuple[bytes, bytes]] | None = None,
    ) -> None:
        """Accept the WebTransport connection.
        
        Args:
            headers: Optional additional headers to send with the accept response.
        """
        if self.application_state != WebTransportState.CONNECTING:
            raise RuntimeError(
                'WebTransport connection cannot be accepted in the "%s" state.'
                % self.application_state.name
            )
        
        message: Message = {"type": "webtransport.accept"}
        if headers is not None:
            message["headers"] = list(headers)
        await self.send(message)

    def _raise_on_disconnect(self, message: Message) -> None:
        """Raise WebTransportDisconnect if message is a disconnect."""
        if message["type"] == "webtransport.disconnect":
            raise WebTransportDisconnect()

    async def receive_stream_data(self) -> tuple[int, bytes, bool]:
        """Receive data from a WebTransport stream.
        
        Returns:
            A tuple of (stream_id, data, is_finished).
            
        Raises:
            WebTransportDisconnect: If the connection is closed.
        """
        while True:
            message = await self.receive()
            self._raise_on_disconnect(message)
            
            if message["type"] == "webtransport.stream.receive":
                stream_id = message["stream_id"]
                data = message.get("data", b"")
                more_body = message.get("more_body", True)
                return stream_id, data, not more_body
            # Ignore other message types and continue waiting

    async def receive_datagram(self) -> bytes:
        """Receive an unreliable datagram.
        
        Returns:
            The datagram data.
            
        Raises:
            WebTransportDisconnect: If the connection is closed.
        """
        while True:
            message = await self.receive()
            self._raise_on_disconnect(message)
            
            if message["type"] == "webtransport.datagram.receive":
                return message.get("data", b"")
            # Ignore other message types and continue waiting

    async def send_stream_data(
        self,
        stream_id: int,
        data: bytes,
        finish: bool = False,
    ) -> None:
        """Send data on a WebTransport stream.
        
        Args:
            stream_id: The QUIC stream ID.
            data: The data to send.
            finish: If True, signal the end of the stream (FIN).
        """
        await self.send({
            "type": "webtransport.stream.send",
            "stream_id": stream_id,
            "data": data,
            "finish": finish,
        })

    async def send_datagram(self, data: bytes) -> None:
        """Send an unreliable datagram.
        
        Args:
            data: The datagram data to send.
        """
        await self.send({
            "type": "webtransport.datagram.send",
            "data": data,
        })

    async def close(self, code: int = 0, reason: str | None = None) -> None:
        """Close the WebTransport connection.
        
        Args:
            code: Optional close code.
            reason: Optional close reason.
        """
        message: Message = {"type": "webtransport.close"}
        if code != 0:
            message["code"] = code
        if reason:
            message["reason"] = reason
        await self.send(message)


class WebTransportClose:
    """ASGI application that closes a WebTransport connection."""
    
    def __init__(self, code: int = 0, reason: str | None = None) -> None:
        self.code = code
        self.reason = reason or ""

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        message: Message = {"type": "webtransport.close"}
        if self.code != 0:
            message["code"] = self.code
        if self.reason:
            message["reason"] = self.reason
        await send(message)
