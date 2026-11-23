"""STC USB-ICE 协议编解码与同步调试会话。

阶段说明
--------
本模块实现已从真实抓包核对过的请求编码、两类设备回复解析、CPU 状态解码，
以及只依赖注入传输对象的同步 ``IceSession``。本阶段不连接硬件，也未做真实
设备验收；后续集成方仍需在目标板上复核暂停、继续和事件时序。

协议边界（按 64 字节 HID 报告自行推导并已用抓包样例核对）
--------------------------------------------------------
* 主机请求：``FF 5A LEN CMD PAYLOAD... CS``，其余补零到 64。
  ``LEN`` 包含 ``CMD``、负载和校验；所有有效字节的 sum8 必须为 0。
  单包负载最大 59 字节。
* 数据回复：``LEN 02 DATA... CS``。``LEN`` 包含类型、数据和校验；
  从类型到校验的 sum8 为 0（不计最前面的 ``LEN``）。单包数据最大 61 字节。
* 事件回复：固定 ``07 06 <5 字节内容> 04``，不适用普通 sum8 校验。
* 内存写请求的固定协议开销为 11 字节，所以单包数据最大为 53 字节。
  这是 ``64 - (FF 5A LEN CMD space addr4 count CS)`` 的直接结果。

事件归属限制
------------
抓包中的 06 事件内容为五个零字节时，既可能是命令确认，也可能是运行停止；
协议本身没有可区分二者的序号或标签。同步会话采用以下保守规则：

* 每次命令只把发送后的第一条回复当作该命令的回复；
* 发送命令前用零超时读取清空已经到达的旧事件，并放入待取事件队列；
* ``resume`` 的第一条事件作为确认，随后立即到达的事件保留给 ``poll_event``；
* ``halt`` 先清理旧事件；若首条回复明显是带 PC 的停止事件，则把它保留并
  尝试读取紧随其后的确认，避免把旧停止误当成当前确认；
* 数据命令收到事件、控制命令收到数据、或任何格式/长度/校验错误都抛出
  ``ProtocolError``，不会静默吞掉。

仍然存在一个无法从协议内容消除的竞态：若零内容停止事件恰好在命令发送前的
清理之后、发送之后到达，它与零内容确认无法区分。调用方应把 ``poll_event``
返回的事件视为“设备报告的事件”，不要把事件内容当作命令序列号。
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import threading
import time
from typing import Deque, Union

from .transport import (
    Transport,
    TransportDisconnected,
    TransportError,
    TransportTimeout,
)


REPORT_SIZE = 64
REQUEST_MAGIC = b"\xFF\x5A"
DATA_RESPONSE_TYPE = 0x02
EVENT_RESPONSE_TYPE = 0x06
EVENT_LENGTH = 0x07
EVENT_TERMINATOR = 0x04

MAX_OUT_PAYLOAD = 59
MAX_IN_DATA = 61
MAX_WRITE_DATA = 53
MAX_STATE_SIZE = 46
MAX_IO_COUNT = 255
MAX_TIMEOUT_MS = 60_000
MAX_DRAIN_EVENTS = 64

CMD_QUERY = 0x00
CMD_WRITE = 0x02
CMD_READ = 0x04
CMD_CONTROL = 0x08


class IceError(RuntimeError):
    """STC USB-ICE 层的基类异常。"""


class ProtocolError(IceError):
    """设备回复或调用参数不符合已验证协议。"""


class IceTimeoutError(IceError):
    """在限定时间内没有收到完整、符合预期的设备回复。"""


class IceDisconnectedError(IceError):
    """HID 设备断开、未打开或底层写入失败。"""


class UnsupportedOperationError(IceError):
    """请求了尚未验证或不支持的调试操作。"""


@dataclass(frozen=True)
class Request:
    """解码后的主机请求；``raw`` 始终保留完整 64 字节报告。"""

    command: int
    payload: bytes
    raw: bytes


@dataclass(frozen=True)
class DataResponse:
    """类型 02 的数据回复。"""

    data: bytes
    raw: bytes


@dataclass(frozen=True)
class Event:
    """类型 06 事件回复。

    ``content`` 是协议中的五字节事件内容；``raw`` 保留完整 64 字节报告。
    """

    content: bytes
    raw: bytes = b""

    @property
    def payload(self) -> bytes:
        """五字节事件内容的别名，便于调用方统一处理。"""

        return self.content

    @property
    def is_zero(self) -> bool:
        """内容是否全零；全零事件可能是确认，也可能是停止。"""

        return self.content == b"\x00" * 5

    @property
    def version_text(self) -> str | None:
        """若事件是版本回复（``00 + ASCII``），返回文本。"""

        if len(self.content) != 5 or self.content[0] != 0x00:
            return None
        body = self.content[1:]
        if not body or any(byte < 0x20 or byte > 0x7E for byte in body):
            return None
        try:
            return body.decode("ascii")
        except UnicodeDecodeError:
            return None

    @property
    def pc(self) -> int | None:
        """若事件带有明确的停止 PC（``00 + BE32 PC``），返回地址。"""

        if len(self.content) != 5 or self.content[0] != 0x00:
            return None
        body = self.content[1:]
        if not any(body) or self.version_text is not None:
            return None
        return int.from_bytes(body, "big")


@dataclass(frozen=True)
class State:
    """46 字节原始 CPU 状态及按大端解释的字段。"""

    raw: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.raw, (bytes, bytearray, memoryview)):
            raise TypeError("State.raw 必须是字节串")
        raw = bytes(self.raw)
        if len(raw) != MAX_STATE_SIZE:
            raise ValueError(
                f"CPU 状态必须为 {MAX_STATE_SIZE} 字节，实际为 {len(raw)} 字节"
            )
        object.__setattr__(self, "raw", raw)

    @property
    def heap(self) -> bytes:
        """寄存器堆原始 32 字节（偏移 0..31）。"""

        return self.raw[0:32]

    @property
    def dpx(self) -> int:
        """DPX/DR56，大端 32 位（偏移 32..35）。"""

        return int.from_bytes(self.raw[32:36], "big")

    @property
    def spx(self) -> int:
        """SPX/DR60，大端 32 位（偏移 36..39）。"""

        return int.from_bytes(self.raw[36:40], "big")

    @property
    def psw(self) -> int:
        """PSW（偏移 40）。"""

        return self.raw[40]

    @property
    def psw1(self) -> int:
        """PSW1（偏移 41）。"""

        return self.raw[41]

    @property
    def pc(self) -> int:
        """PC，大端 32 位（偏移 42..45）。"""

        return int.from_bytes(self.raw[42:46], "big")


def _require_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} 必须是整数")
    return value


def _validate_report(report: bytes | bytearray | memoryview) -> bytes:
    if not isinstance(report, (bytes, bytearray, memoryview)):
        raise ProtocolError("HID 报告必须是字节串")
    raw = bytes(report)
    if len(raw) != REPORT_SIZE:
        raise ProtocolError(
            f"HID 报告必须为 {REPORT_SIZE} 字节，实际为 {len(raw)} 字节"
        )
    return raw


def _validate_zero_padding(raw: bytes, effective_length: int) -> None:
    if effective_length < 0 or effective_length > REPORT_SIZE:
        raise ProtocolError(f"有效报告长度越界：{effective_length}")
    if any(raw[effective_length:]):
        raise ProtocolError(
            f"有效数据之后的 {REPORT_SIZE - effective_length} 字节填充必须全为 0"
        )


def encode_request(command: int, payload: bytes | bytearray | memoryview = b"") -> bytes:
    """编码一条主机请求并补零到 64 字节。

    ``LEN`` 包含命令、负载和校验字节。单包负载上限是 59 字节，因此普通内存
    写在带 6 字节空间/地址/数量头时最多携带 53 字节数据。
    """

    command = _require_int(command, "command")
    if not 0 <= command <= 0xFF:
        raise ValueError("command 必须在 0..255 范围内")
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise TypeError("payload 必须是字节串")
    body = bytes(payload)
    if len(body) > MAX_OUT_PAYLOAD:
        raise ValueError(
            f"单包负载最多 {MAX_OUT_PAYLOAD} 字节，实际为 {len(body)} 字节"
        )
    length = 1 + len(body) + 1
    if length > 0x3D:
        raise ValueError("请求 LEN 超出 64 字节报告允许范围")
    effective_head = REQUEST_MAGIC + bytes((length, command)) + body
    checksum = (-sum(effective_head)) & 0xFF
    effective = effective_head + bytes((checksum,))
    return effective + bytes(REPORT_SIZE - len(effective))


def decode_request(report: bytes | bytearray | memoryview) -> Request:
    """严格解析并校验一条 64 字节主机请求，主要用于测试和诊断。"""

    raw = _validate_report(report)
    if raw[0:2] != REQUEST_MAGIC:
        raise ProtocolError(
            f"请求 magic 应为 FF 5A，实际为 {raw[0:2].hex().upper()}"
        )
    length = raw[2]
    if length < 2:
        raise ProtocolError(f"请求 LEN={length} 过短，至少应包含命令和校验")
    effective_length = 3 + length
    if effective_length > REPORT_SIZE:
        raise ProtocolError(
            f"请求 LEN={length} 给出有效长度 {effective_length}，超过 64"
        )
    _validate_zero_padding(raw, effective_length)
    effective = raw[:effective_length]
    if sum(effective) & 0xFF:
        raise ProtocolError(
            f"请求 sum8 应为 0，实际为 {sum(effective) & 0xFF:02X}"
        )
    command = raw[3]
    payload = raw[4 : effective_length - 1]
    return Request(command=command, payload=payload, raw=raw)


def decode_response(
    report: bytes | bytearray | memoryview,
    *,
    expected_data_length: int | None = None,
) -> Union[DataResponse, Event]:
    """严格解析类型 02 数据回复或类型 06 事件回复。

    不能通过删除末尾零字节推断长度；本函数始终使用报告开头的 ``LEN`` 和
    事件固定长度，并额外要求有效部分之后的填充全为零。
    """

    raw = _validate_report(report)
    length = raw[0]
    if length == 0:
        raise ProtocolError("IN 回复的 LEN 不能为 0")
    effective_length = 1 + length
    if effective_length > REPORT_SIZE:
        raise ProtocolError(
            f"IN LEN={length} 给出有效长度 {effective_length}，超过 64"
        )
    _validate_zero_padding(raw, effective_length)
    response_type = raw[1]

    if response_type == DATA_RESPONSE_TYPE:
        if length < 3:
            raise ProtocolError("类型 02 回复至少应包含类型、数据和校验")
        if sum(raw[1:effective_length]) & 0xFF:
            raise ProtocolError(
                "类型 02 回复从类型到校验的 sum8 应为 0，"
                f"实际为 {sum(raw[1:effective_length]) & 0xFF:02X}"
            )
        data = raw[2:length]
        if len(data) != length - 2:
            raise ProtocolError("类型 02 回复的数据长度与 LEN 不一致")
        if expected_data_length is not None:
            expected_data_length = _require_int(
                expected_data_length, "expected_data_length"
            )
            if expected_data_length < 0:
                raise ValueError("expected_data_length 不能为负数")
            if len(data) != expected_data_length:
                raise ProtocolError(
                    f"数据回复长度应为 {expected_data_length}，实际为 {len(data)}"
                )
        return DataResponse(data=data, raw=raw)

    if response_type == EVENT_RESPONSE_TYPE:
        if length != EVENT_LENGTH:
            raise ProtocolError(
                f"类型 06 事件的 LEN 必须为 07，实际为 {length:02X}"
            )
        if raw[7] != EVENT_TERMINATOR:
            raise ProtocolError(
                f"事件终止符应为 04，实际为 {raw[7]:02X}"
            )
        return Event(content=raw[2:7], raw=raw)

    raise ProtocolError(f"未知的 IN 回复类型 {response_type:02X}")


def decode_data_response(
    report: bytes | bytearray | memoryview,
    *,
    expected_data_length: int | None = None,
) -> DataResponse:
    """只接受类型 02 数据回复。"""

    response = decode_response(
        report, expected_data_length=expected_data_length
    )
    if not isinstance(response, DataResponse):
        raise ProtocolError("期望类型 02 数据回复，实际收到类型 06 事件")
    return response


def decode_event(report: bytes | bytearray | memoryview) -> Event:
    """只接受类型 06 事件回复。"""

    response = decode_response(report)
    if not isinstance(response, Event):
        raise ProtocolError("期望类型 06 事件，实际收到类型 02 数据回复")
    return response


class IceSession:
    """严格校验、串行执行的 STC USB-ICE 同步会话。

    传输对象必须提供 ``write_report(report, timeout_ms=None)`` 和
    ``read_report(timeout_ms)``。构造会话不会打开或枚举 USB 设备；测试可注入
    Fake/mock 传输对象。所有方法在会话锁内串行执行。
    """

    def __init__(self, transport: Transport, *, timeout_ms: int = 1_000) -> None:
        self._check_transport(transport)
        timeout_ms = _require_int(timeout_ms, "timeout_ms")
        if not 1 <= timeout_ms <= MAX_TIMEOUT_MS:
            raise ValueError(f"timeout_ms 必须在 1..{MAX_TIMEOUT_MS} 范围内")
        self.transport = transport
        self.timeout_ms = timeout_ms
        self._events: Deque[Event] = deque()
        self._lock = threading.RLock()

    @staticmethod
    def _check_transport(transport):
        if not callable(getattr(transport, "write_report", None)):
            raise TypeError("transport 缺少 write_report(report, timeout_ms=None)")
        if not callable(getattr(transport, "read_report", None)):
            raise TypeError("transport 缺少 read_report(timeout_ms)")

    # ---- 传输适配 -----------------------------------------------------

    def _write_report(self, report: bytes) -> None:
        try:
            self.transport.write_report(report, timeout_ms=self.timeout_ms)
        except TransportTimeout as exc:
            raise IceTimeoutError(f"写入 USB-ICE 报告超时：{exc}") from exc
        except TransportDisconnected as exc:
            raise IceDisconnectedError(f"USB-ICE 设备已断开：{exc}") from exc
        except TimeoutError as exc:
            raise IceTimeoutError(f"写入 USB-ICE 报告超时：{exc}") from exc
        except OSError as exc:
            raise IceDisconnectedError(f"写入 USB-ICE 设备失败：{exc}") from exc
        except TransportError as exc:
            raise IceError(f"USB-ICE 传输失败：{exc}") from exc

    def _read_report(self, timeout_ms: int) -> bytes:
        try:
            report = self.transport.read_report(timeout_ms)
        except TransportTimeout as exc:
            raise IceTimeoutError(
                f"等待 USB-ICE 回复超时（{timeout_ms} ms）"
            ) from exc
        except TransportDisconnected as exc:
            raise IceDisconnectedError(f"USB-ICE 设备已断开：{exc}") from exc
        except TimeoutError as exc:
            raise IceTimeoutError(
                f"等待 USB-ICE 回复超时（{timeout_ms} ms）"
            ) from exc
        except OSError as exc:
            raise IceDisconnectedError(f"读取 USB-ICE 设备失败：{exc}") from exc
        except TransportError as exc:
            raise IceError(f"USB-ICE 传输失败：{exc}") from exc
        if not isinstance(report, (bytes, bytearray, memoryview)):
            raise ProtocolError("传输层返回的 HID 报告不是字节串")
        return _validate_report(report)

    def _drain_stale_events(self) -> None:
        """把发送新命令前已经到达的事件移入队列，绝不删除。"""

        for _ in range(MAX_DRAIN_EVENTS):
            try:
                report = self._read_report(0)
            except IceTimeoutError:
                return
            response = decode_response(report)
            if not isinstance(response, Event):
                raise ProtocolError(
                    "会话没有未完成命令，却收到类型 02 数据回复；"
                    "无法安全归属，已停止解析"
                )
            self._events.append(response)
        raise ProtocolError(
            f"一次清理收到超过 {MAX_DRAIN_EVENTS} 条事件；"
            "设备可能持续产生事件，拒绝无限读取"
        )

    def _exchange(
        self, command: int, payload: bytes, *, expected_data_length: int | None = None
    ) -> Union[DataResponse, Event]:
        self._drain_stale_events()
        self._write_report(encode_request(command, payload))
        return decode_response(
            self._read_report(self.timeout_ms),
            expected_data_length=expected_data_length,
        )

    def _data_exchange(
        self, command: int, payload: bytes, expected_data_length: int
    ) -> DataResponse:
        response = self._exchange(
            command, payload, expected_data_length=expected_data_length
        )
        if not isinstance(response, DataResponse):
            raise ProtocolError(
                f"命令 {command:02X} 期望数据回复，实际收到类型 06 事件"
            )
        return response

    def _event_exchange(self, command: int, payload: bytes) -> Event:
        response = self._exchange(command, payload)
        if not isinstance(response, Event):
            raise ProtocolError(
                f"命令 {command:02X} 期望事件回复，实际收到类型 02 数据回复"
            )
        if response.version_text is not None and command != CMD_QUERY:
            raise ProtocolError(
                f"命令 {command:02X} 收到了不属于该命令的版本事件"
            )
        return response

    # ---- 基础调试接口 -------------------------------------------------

    def initialize_debug(
        self, entry_pc: int = 0xFF0000, settle_seconds: float = 2.0
    ) -> tuple[str, State]:
        """按 Keil 完整抓包建立新的调试会话，返回版本和初始 CPU 状态。

        对应 keil sma.pcapng 的 1733..1743 帧：查询版本、空间 0 的
        零长度入口请求、确认、等待 2 秒、读取状态。此请求只用于启动
        FF0000 的新会话，不开放通用 set_pc，也不先发暂停或自动运行。
        """
        entry_pc = _require_int(entry_pc, "entry_pc")
        if entry_pc != 0xFF0000:
            raise ValueError("已验证的 USB-ICE 启动入口仅为 FF0000")
        if (isinstance(settle_seconds, bool)
                or not isinstance(settle_seconds, (int, float))
                or not 2.0 <= settle_seconds <= 60.0):
            raise ValueError("启动等待时间必须为 2..60 秒")
        with self._lock:
            version = self.version()
            if version != "V4.0":
                raise ProtocolError(f"尚未验证 {version} 的 Keil 启动流程")
            # 原始请求 FF5A08020000FF0000009E；不使用通用内存写入，
            # 后者要求至少一个数据字节，语义与本请求不同。
            event = self._event_exchange(
                CMD_WRITE, b"\x00" + entry_pc.to_bytes(4, "big") + b"\x00"
            )
            if event.content != b"\x00" * 5:
                raise ProtocolError("USB-ICE 启动入口请求未收到预期确认")
            time.sleep(settle_seconds)
            state = self.read_state()
            if state.pc != entry_pc:
                raise ProtocolError(
                    f"USB-ICE 启动入口不匹配：期望 {entry_pc:06X}，"
                    f"实际 {state.pc:06X}"
                )
            return version, state

    def version(self) -> str:
        """查询固件版本，返回例如 ``V4.0`` 的 ASCII 文本。"""

        with self._lock:
            response = self._exchange(CMD_QUERY, b"\x00")
            if isinstance(response, Event):
                text = self._version_from_bytes(response.content, "事件")
            else:
                text = self._version_from_bytes(response.data, "数据回复")
            self._drain_stale_events()
            return text

    @staticmethod
    def _version_from_bytes(data: bytes, source: str) -> str:
        if len(data) != 5:
            raise ProtocolError(
                f"版本{source}必须为 5 字节，实际为 {len(data)} 字节"
            )
        if data[0] != 0x00:
            raise ProtocolError("版本回复首字节应为 00")
        body = data[1:]
        if not body or any(byte < 0x20 or byte > 0x7E for byte in body):
            raise ProtocolError("版本文本必须是非空可打印 ASCII")
        try:
            return body.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ProtocolError("版本文本不是有效 ASCII") from exc

    def read_state(self) -> State:
        """读取 46 字节 CPU 原始状态并返回 :class:`State`。"""

        with self._lock:
            response = self._data_exchange(
                CMD_QUERY, b"\x01", expected_data_length=MAX_STATE_SIZE
            )
            return State(response.data)

    def read_memory(self, space: int, address: int, count: int) -> bytes:
        """从指定空间读取 1..255 字节，超过单包上限时自动分块。

        空间 5 是代码修改空间，读取行为尚未验证，因此明确拒绝；允许读取
        空间 0..4。返回值按地址递增顺序拼接。
        """

        space = _require_int(space, "space")
        address = _require_int(address, "address")
        count = _require_int(count, "count")
        if not 0 <= space <= 4:
            if space == 5:
                raise UnsupportedOperationError(
                    "空间 5 仅允许通过 write_memory 做代码修改，不支持读取"
                )
            raise ValueError("space 必须在 0..4 范围内")
        if not 1 <= count <= MAX_IO_COUNT:
            raise ValueError(f"count 必须在 1..{MAX_IO_COUNT} 范围内")
        if not 0 <= address <= 0xFFFFFFFF:
            raise ValueError("address 必须在 0..0xFFFFFFFF 范围内")
        if address + count - 1 > 0xFFFFFFFF:
            raise ValueError("读取范围越过 32 位地址上限")

        chunks: list[bytes] = []
        with self._lock:
            offset = 0
            while offset < count:
                chunk_count = min(MAX_IN_DATA, count - offset)
                chunk_address = address + offset
                payload = (
                    bytes((space,))
                    + chunk_address.to_bytes(4, "big")
                    + bytes((chunk_count,))
                )
                response = self._data_exchange(
                    CMD_READ, payload, expected_data_length=chunk_count
                )
                chunks.append(response.data)
                offset += chunk_count
        return b"".join(chunks)

    def write_memory(
        self, space: int, address: int, data: bytes | bytearray | memoryview
    ) -> None:
        """向指定空间写入 1..255 字节，超过单包上限时自动分块。

        空间 0..5 均允许写入；空间 5 专门用于代码修改。写入设备以 06 事件
        确认，本方法不把该确认错误地当成运行停止事件。
        """

        space = _require_int(space, "space")
        address = _require_int(address, "address")
        if not 0 <= space <= 5:
            raise ValueError("space 必须在 0..5 范围内")
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data 必须是字节串")
        body = bytes(data)
        if not 1 <= len(body) <= MAX_IO_COUNT:
            raise ValueError(f"写入数据长度必须在 1..{MAX_IO_COUNT} 范围内")
        if not 0 <= address <= 0xFFFFFFFF:
            raise ValueError("address 必须在 0..0xFFFFFFFF 范围内")
        if address + len(body) - 1 > 0xFFFFFFFF:
            raise ValueError("写入范围越过 32 位地址上限")

        with self._lock:
            offset = 0
            while offset < len(body):
                chunk = body[offset : offset + MAX_WRITE_DATA]
                chunk_address = address + offset
                payload = (
                    bytes((space,))
                    + chunk_address.to_bytes(4, "big")
                    + bytes((len(chunk),))
                    + chunk
                )
                event = self._event_exchange(CMD_WRITE, payload)
                # 带 PC 的事件是真实设备状态，保留而不是把它解释成写确认。
                if event.pc is not None:
                    self._events.append(event)
                self._drain_stale_events()
                offset += len(chunk)

    def resume(self) -> None:
        """继续运行目标程序。"""

        with self._lock:
            event = self._event_exchange(CMD_CONTROL, b"\x00")
            # 首条回复属于本次 resume；若它已携带停止 PC，保留为待取事件。
            if event.pc is not None:
                self._events.append(event)
            self._drain_stale_events()

    def halt(self, *, expect_running: bool = False) -> None:
        """暂停目标；运行中必须收到确认，不能用状态查询替代停止确认。"""

        if not isinstance(expect_running, bool):
            raise TypeError("expect_running 必须为 bool")
        with self._lock:
            self._drain_stale_events()
            self._write_report(encode_request(CMD_QUERY, b"\x02"))
            try:
                first_report = self._read_report(self.timeout_ms)
            except IceTimeoutError as exc:
                if expect_running:
                    # 只在已知暂停的设备上，V4.0 才有不回复重复暂停的现象。
                    # 运行中超时必须保留首个失败，不能追加读取并将其算作已停止。
                    raise IceTimeoutError(
                        f"暂停请求已发送，但 {self.timeout_ms} ms 内未收到停止确认；"
                        "目标停止状态未确认"
                    ) from exc
                # V4.0 已停下时不会再次确认暂停。仍须通过一次完整、校验正确的
                # CPU 快照验证调试上下文可读；状态也读不到时保留异常，不能假报成功。
                self.read_state()
                return
            first = decode_event(first_report)
            if first.version_text is not None:
                raise ProtocolError("暂停命令收到了版本事件")

            if first.pc is not None:
                # 带 PC 的事件明显是停止报告。它可能是本轮暂停结果，也可能
                # 是上一轮迟到的停止事件；先保留，再尝试读取紧随其后的确认。
                self._events.append(first)
                try:
                    second_report = self._read_report(0)
                except IceTimeoutError:
                    return
                second = decode_event(second_report)
                if second.version_text is not None:
                    raise ProtocolError("暂停命令收到了版本事件")
                if second.pc is not None:
                    self._events.append(second)
            self._drain_stale_events()

    def step(self, instruction_window: bytes | bytearray | memoryview) -> Event:
        """执行一条指令。

        ``instruction_window`` 必须是当前 PC 处正好 4 字节的本地机器码窗口，
        不是地址。设备通常返回带新 PC 的 06 事件；本方法返回该事件。
        """

        if not isinstance(instruction_window, (bytes, bytearray, memoryview)):
            raise TypeError("instruction_window 必须是 4 字节机器码")
        window = bytes(instruction_window)
        if len(window) != 4:
            raise ValueError(
                f"instruction_window 必须正好 4 字节，实际为 {len(window)} 字节"
            )
        with self._lock:
            event = self._event_exchange(
                CMD_CONTROL, b"\x01" + window + b"\x00"
            )
            self._drain_stale_events()
            return event

    def poll_event(self, timeout_ms: int) -> Event | None:
        """取出下一个事件；超时返回 ``None``。

        已归属当前命令的确认不会进入队列；队列中的后续事件优先返回。
        收到数据回复说明会话已失去安全归属，抛出 ``ProtocolError``。
        """

        timeout_ms = _require_int(timeout_ms, "timeout_ms")
        if not 0 <= timeout_ms <= MAX_TIMEOUT_MS:
            raise ValueError(f"timeout_ms 必须在 0..{MAX_TIMEOUT_MS} 范围内")
        with self._lock:
            if self._events:
                return self._events.popleft()
            try:
                report = self._read_report(timeout_ms)
            except IceTimeoutError:
                return None
            response = decode_response(report)
            if not isinstance(response, Event):
                raise ProtocolError(
                    "poll_event 收到了类型 02 数据回复，无法安全归属"
                )
            return response

    def set_pc(self, address: int) -> None:
        """PC 重定位的副作用尚未验证，当前版本明确不支持。"""

        raise UnsupportedOperationError(
            "set_pc 尚未验证；抓包中的空间 0、数量 0 写请求不构成安全的 PC 设置接口"
        )

