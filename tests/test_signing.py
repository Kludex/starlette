from unittest import mock

from starlette.signing import TimestampSigner, _b64_decode, _b64_encode


class TestTimestampSigner:
    def test_sign_basic(self) -> None:
        signer = TimestampSigner("secret")
        signed = signer.sign(b"hello")
        assert isinstance(signed, bytes)
        assert len(signed) > 30

    def test_round_trip(self) -> None:
        signer = TimestampSigner("secret")
        test_cases = [
            b"",
            b"a",
            b"hello world",
            b"\x00\x01\x02\xff\xfe\xfd",
            b"\x00\x00\x00\x00",
            b"x" * 1000,
            b'{"user": "alice", "id": 123}',
            "Hello 世界 🌍".encode(),
        ]
        for data in test_cases:
            signed = signer.sign(data)
            unsigned = signer.unsign(signed)
            assert unsigned == data

    def test_output_is_ascii(self) -> None:
        signer = TimestampSigner("secret")
        data = "Hello 世界 🌍".encode()
        signed = signer.sign(data)
        signed.decode("ascii")
        assert all(b < 128 for b in signed)

    def test_no_padding_in_output(self) -> None:
        signer = TimestampSigner("secret")
        for size in range(10):
            data = b"x" * size
            signed = signer.sign(data)
            assert b"=" not in signed

    def test_no_forbidden_characters(self) -> None:
        signer = TimestampSigner("secret")
        forbidden = set(b' ,;"\\')
        test_data = [
            b"simple",
            b'{"user": "alice", "roles": ["admin"]}',
            b"\x00\xff" * 10,
            b"x" * 10,
        ]
        for data in test_data:
            signed = signer.sign(data)
            assert not any(c in forbidden for c in signed)
            valid_chars = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
            assert all(c in valid_chars for c in signed)


class TestTimestampValidation:
    def test_unsign_with_valid_max_age(self) -> None:
        signer = TimestampSigner("secret")
        signed = signer.sign(b"data")
        assert signer.unsign(signed, max_age=10) == b"data"
        assert signer.unsign(signed, max_age=1000) == b"data"

    def test_unsign_with_expired_max_age(self) -> None:
        signer = TimestampSigner("secret")
        with mock.patch("time.time", return_value=1000):
            signed = signer.sign(b"data")

        with mock.patch("time.time", return_value=1003):
            assert signer.unsign(signed, max_age=1) is None
            assert signer.unsign(signed, max_age=0) is None

        assert signer.unsign(signed, max_age=None) == b"data"


class TestSecurityAttacks:
    def test_tampered_signature(self) -> None:
        signer = TimestampSigner("secret")
        signed = signer.sign(b"data")

        tampered_byte = bytes([signed[-23] ^ 0xFF])
        tampered = signed[:-23] + tampered_byte + signed[-22:]
        assert signer.unsign(tampered) is None

        tampered_byte = bytes([signed[-12] ^ 0xFF])
        tampered = signed[:-12] + tampered_byte + signed[-11:]
        assert signer.unsign(tampered) is None

    def test_tampered_payload(self) -> None:
        signer = TimestampSigner("secret")
        signed = signer.sign(b"data")
        tampered = b"XXXX" + signed[4:]
        assert signer.unsign(tampered) is None

    def test_signature_from_different_payload(self) -> None:
        signer = TimestampSigner("secret")
        signed1 = signer.sign(b"data1")
        signed2 = signer.sign(b"data2")

        combined1 = signed1[:-23]
        suffix2 = signed2[-23:]
        mixed = combined1 + suffix2
        assert signer.unsign(mixed) is None


class TestMalformedData:
    def test_minimum_length_requirement(self) -> None:
        signer = TimestampSigner("secret")
        assert signer.unsign(b"") is None
        assert signer.unsign(b"a") is None
        assert signer.unsign(b"a" * 20) is None
        assert signer.unsign(b"a" * 29) is None
        assert signer.unsign(b"short_") is None
        assert signer.unsign(b"a" * 29 + b"_") is None

    def test_missing_version_marker(self) -> None:
        signer = TimestampSigner("secret")
        signed = signer.sign(b"data")

        without_marker = signed[:-1]
        assert signer.unsign(without_marker) is None

        wrong_marker = signed[:-1] + b"X"
        assert signer.unsign(wrong_marker) is None

    def test_invalid_base64_in_combined_data(self) -> None:
        signer = TimestampSigner("secret")
        signed = signer.sign(b"data")
        tampered = b"!!!!!!AAAAA" + signed[-23:]
        assert signer.unsign(tampered) is None

    def test_invalid_base64_in_signature(self) -> None:
        signer = TimestampSigner("secret")
        signed = signer.sign(b"data")
        tampered = signed[:-23] + b"!" * 22 + b"_"
        assert signer.unsign(tampered) is None


class TestBase64UrlHelpers:
    def test_encode_basic(self) -> None:
        assert _b64_encode(b"hello") == b"aGVsbG8"
        assert _b64_encode(b"") == b""

    def test_decode_invalid_returns_none(self) -> None:
        assert _b64_decode(b"A") is None
        assert _b64_decode(b"AAAAA") is None

    def test_round_trip(self) -> None:
        test_cases = [b"", b"a", b"hello world", b"\x00\x01\x02\xff\xfe\xfd"]
        for data in test_cases:
            encoded = _b64_encode(data)
            decoded = _b64_decode(encoded)
            assert decoded == data
