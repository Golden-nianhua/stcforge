"""MCS-251 UART monitor, based on the serial branch of Keil STCMON251."""
from time import monotonic, sleep

from .ice import (
    CMD_CONTROL, CMD_QUERY, DataResponse, Event, IceDisconnectedError,
    IceSession, IceTimeoutError, ProtocolError, encode_request,
)

DEFAULT_BAUD = 115200


class SerialLink:
    def __init__(self, port, baud=DEFAULT_BAUD):
        try:
            import serial
        except ImportError as exc:
            raise ImportError("UART debugging requires STCForge's uart extra") from exc
        self._write_timeout_error = serial.SerialTimeoutException
        self.port = serial.Serial(port=None, baudrate=baud, bytesize=8, parity="N",
                                  stopbits=2, timeout=0, write_timeout=1)
        self.port.dtr = self.port.rts = False
        self.port.port = port
        self.port.open()

    def write(self, data, timeout_ms):
        try:
            self.port.write_timeout = timeout_ms / 1000
            if self.port.write(data) != len(data):
                raise IceTimeoutError("Incomplete UART monitor write")
        except self._write_timeout_error as exc:
            raise IceTimeoutError(f"UART monitor write timed out: {exc}") from exc
        except (OSError, ValueError) as exc:
            raise IceDisconnectedError(f"UART monitor write failed: {exc}") from exc

    def read(self, size, timeout_ms):
        try:
            self.port.timeout = timeout_ms / 1000
            return self.port.read(size)
        except (OSError, ValueError) as exc:
            raise IceDisconnectedError(f"UART monitor read failed: {exc}") from exc

    def discard_input(self):
        try:
            self.port.reset_input_buffer()
        except OSError as exc:
            raise IceDisconnectedError(f"UART monitor RX purge failed: {exc}") from exc

    def close(self):
        self.port.close()


class SerialIceSession(IceSession):
    """Share memory/state commands, not HID framing or execution-state handling."""

    @staticmethod
    def _check_transport(link):
        for name in ("read", "write", "discard_input", "close"):
            if not callable(getattr(link, name, None)):
                raise TypeError(f"UART link is missing {name}()")

    def _write_report(self, report):
        self.transport.write(report[:3 + report[2]], self.timeout_ms)

    def _read_report(self, timeout_ms):
        raise NotImplementedError("UART replies have command-specific lengths")

    def _drain_stale_events(self):
        # On UART an idle read can consume a raw execution-stop marker.
        pass

    def _read_exact(self, count, timeout_ms):
        data = bytearray()
        deadline = monotonic() + timeout_ms / 1000
        while len(data) < count:
            chunk = self.transport.read(count - len(data), max(0, round((deadline - monotonic()) * 1000)))
            if not chunk:
                raise IceTimeoutError(f"UART monitor reply incomplete ({len(data)}/{count} bytes)")
            data.extend(chunk)
            if len(data) < count and monotonic() >= deadline:
                raise IceTimeoutError(f"UART monitor reply incomplete ({len(data)}/{count} bytes)")
        return bytes(data)

    def _event_exchange(self, command, payload):
        self._write_report(encode_request(command, payload))
        raw = self._read_exact(7, self.timeout_ms)
        if raw[:2] != b"\x06\x00" or raw[-1] != 0x04:
            raise ProtocolError(f"Invalid UART monitor event: {raw.hex(' ')}")
        event = Event(raw[1:6], raw)
        if command != CMD_QUERY and event.version_text is not None:
            raise ProtocolError("Unexpected UART monitor version reply")
        return event

    def _data_exchange(self, command, payload, expected_data_length):
        self._write_report(encode_request(command, payload))
        raw = self._read_exact(expected_data_length + 2, self.timeout_ms)
        if raw[0] != 0x02 or sum(raw) & 0xff:
            raise ProtocolError(f"Invalid UART monitor data reply: {raw.hex(' ')}")
        return DataResponse(raw[1:-1], raw)

    def _handshake(self):
        self.transport.discard_input()
        for _ in range(10):
            self.transport.write(b"\x80", self.timeout_ms)
            first = self.transport.read(1, 100)
            if first and first != b"\x80":
                break
        else:
            raise IceTimeoutError("UART monitor did not answer the 80 handshake")
        self.transport.write(b"\x80", self.timeout_ms)
        second = self._read_exact(1, 100)
        if first + second not in (b"\x00\xff", b"\xff\x00"):
            raise ProtocolError(f"Invalid UART monitor handshake: {(first + second).hex(' ')}")

    def version(self):
        with self._lock:
            return self._version_from_bytes(self._event_exchange(CMD_QUERY, b"\x00").content, "UART")

    def initialize_debug(self):
        with self._lock:
            self._handshake()
            sleep(0.1)
            return self.version(), self.read_state()

    def resume(self):
        with self._lock:
            self._event_exchange(CMD_CONTROL, b"\x00")

    def step(self, instruction_window):
        with self._lock:
            event = super().step(instruction_window)
            if event.pc is not None:
                return event
            state = self.read_state()
            return Event(b"\x00" + state.pc.to_bytes(4, "big"))

    def _confirm_stop(self):
        # Keil drops the rest of the stop notification, re-handshakes and
        # reads PC. Read the complete snapshot so a stray byte is not a stop.
        sleep(0.1)
        self._handshake()
        return self.read_state()

    def halt(self, *, expect_running=False):
        with self._lock:
            if expect_running:
                self.transport.write(b"\xff", self.timeout_ms)
                self._read_exact(1, self.timeout_ms)
                self._confirm_stop()

    def poll_event(self, timeout_ms):
        with self._lock:
            # IceTarget polls with zero timeout while stopped (before run).
            if timeout_ms == 0:
                return None
            if not self.transport.read(1, timeout_ms):
                return None
            state = self._confirm_stop()
            return Event(b"\x00" + state.pc.to_bytes(4, "big"))
