"""STC USB-ICE 的 HID 传输层。

阶段说明
--------
``HidTransport`` 只在显式调用 :meth:`HidTransport.open` 时惰性导入 ``hidapi``
并枚举目标设备；构造对象、导入本模块和创建 ``IceSession`` 都不会连接硬件。
Windows 的 65 字节写入（报告 ID 0 + 64 字节负载）和 64 字节读取已经通过
V4.0 实机的版本查询、状态读取和单指令步进；继续运行后的通信恢复仍待验证。

传输层只负责有界 I/O、报告 ID 规范化和异常分类；协议长度、校验、填充与
事件归属全部由 :mod:`stcforge.ice` 严格处理，避免在此处误删合法的零字节。
"""

from __future__ import annotations

import os
from types import TracebackType
from typing import Any, Callable, Protocol, runtime_checkable


REPORT_SIZE = 64
STC_VID = 0x34BF
STC_PID = 0x1002
MAX_TIMEOUT_MS = 60_000


class TransportError(RuntimeError):
    """传输层基类异常。"""


class TransportTimeout(TransportError):
    """在限定时间内没有收到 HID 报告。"""


class TransportDisconnected(TransportError):
    """设备未打开、断开或底层读写失败。"""


@runtime_checkable
class Transport(Protocol):
    """可注入的 64 字节 HID 报告传输接口。"""

    def write_report(self, report: bytes, *, timeout_ms: int | None = None) -> None:
        """写入一条完整 64 字节报告。"""

    def read_report(self, timeout_ms: int) -> bytes:
        """读取一条完整 64 字节报告；超时抛 :class:`TransportTimeout`。"""


def _validate_timeout(timeout_ms: int | None) -> int | None:
    if timeout_ms is None:
        return None
    if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int):
        raise TypeError("timeout_ms 必须是整数")
    if not 0 <= timeout_ms <= MAX_TIMEOUT_MS:
        raise ValueError(f"timeout_ms 必须在 0..{MAX_TIMEOUT_MS} 范围内")
    return timeout_ms


class HidTransport:
    """通过 hidapi 访问 STC USB-ICE 的显式生命周期传输。

    Parameters
    ----------
    device_path:
        可选，指定 hidapi 的设备路径。省略时 :meth:`open` 会按
        ``VID=0x34BF, PID=0x1002`` 枚举；多设备时必须指定路径。
    module_factory:
        仅用于测试或特殊部署的 hidapi 模块工厂。构造对象时不会调用它。
    read_timeout_ms:
        未显式传入读取超时时的默认值。
    """

    device_name = "STC USB-ICE"
    usb_ids = ((STC_VID, STC_PID),)

    def __init__(
        self,
        device_path: bytes | str | None = None,
        *,
        module_factory: Callable[[], Any] | None = None,
        read_timeout_ms: int = 1_000,
    ) -> None:
        self.device_path = device_path
        self._module_factory = module_factory
        self._module: Any | None = None
        self._device: Any | None = None
        self._opened = False
        self.read_timeout_ms = _validate_timeout(read_timeout_ms)

    @property
    def is_open(self) -> bool:
        return self._opened and self._device is not None

    def open(self) -> None:
        """显式打开设备；重复调用是幂等的。"""

        if self.is_open:
            return
        try:
            module = self._load_module()
            path = self.device_path if self.device_path is not None else self._find_path(module)
            device = module.device()
            try:
                device.open_path(path)
                # cython-hidapi 的 read(size, 0) 会调用 hid_read，而不是
                # hid_read_timeout(..., 0)。句柄默认阻塞，会卡住握手前的旧事件轮询。
                # 只设置本句柄的默认读取模式；正数 timeout 仍由 hid_read_timeout 处理。
                if device.set_nonblocking(1) != 0:
                    raise OSError(f"无法将 {self.device_name} 接口设为非阻塞读取")
            except Exception:
                # 打开或设置读取模式失败时释放已创建的 hidapi device 对象。
                try:
                    device.close()
                except Exception:
                    pass
                raise
        except TransportError:
            raise
        except ImportError as exc:
            raise TransportError(
                "未安装 hidapi；请安装 stcforge 的 usb 可选依赖（hidapi）"
            ) from exc
        except OSError as exc:
            raise TransportDisconnected(
                f"无法打开 {self.device_name}：{exc}"
            ) from exc
        except Exception as exc:
            raise TransportDisconnected(
                f"无法打开 {self.device_name}：{exc}"
            ) from exc
        self._module = module
        self._device = device
        self._opened = True

    def _load_module(self) -> Any:
        if self._module_factory is not None:
            return self._module_factory()
        # 惰性导入：模块顶层和对象构造阶段都不得触发 hidapi 加载。
        import hid  # type: ignore[import-not-found]

        return hid

    @classmethod
    def enumerate_devices(cls, module: Any) -> list:
        try:
            return [entry for vid, pid in cls.usb_ids
                    for entry in module.enumerate(vendor_id=vid, product_id=pid)]
        except Exception as exc:
            raise TransportDisconnected(
                f"枚举 {cls.device_name} 失败：{exc}"
            ) from exc

    @classmethod
    def _find_path(cls, module: Any) -> bytes | str:
        entries = cls.enumerate_devices(module)
        if not entries:
            ids = " / ".join(f"{vid:04X}:{pid:04X}" for vid, pid in cls.usb_ids)
            raise TransportDisconnected(
                f"未找到 {cls.device_name}（{ids}）；请检查连接"
            )
        if len(entries) != 1:
            raise TransportDisconnected(f"发现多个 {cls.device_name}，请通过 --device-path 指定设备")
        path = entries[0].get("path")
        if path is None:
            raise TransportDisconnected("hidapi 返回的目标设备缺少 path 字段")
        return path

    def close(self) -> None:
        """显式关闭设备；未打开或重复关闭均安全。"""

        device, self._device = self._device, None
        self._opened = False
        if device is not None:
            try:
                device.close()
            except Exception as exc:
                raise TransportDisconnected(f"关闭 {self.device_name} 失败：{exc}") from exc

    def __enter__(self) -> "HidTransport":
        self.open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def _require_device(self) -> Any:
        if not self.is_open or self._device is None:
            raise TransportDisconnected(f"{self.device_name} 尚未打开，请先显式调用 open()")
        return self._device

    def write_report(self, report: bytes, *, timeout_ms: int | None = None) -> None:
        """写入 64 字节报告。

        hidapi 的跨平台 API 都要求首字节为报告 ID；本设备使用 ID 0，
        所以各平台均写入 65 字节 ``00 + report``。
        """

        if not isinstance(report, (bytes, bytearray, memoryview)):
            raise TypeError("report 必须是字节串")
        payload = bytes(report)
        if len(payload) != REPORT_SIZE:
            raise ValueError(f"HID 报告必须为 {REPORT_SIZE} 字节，实际为 {len(payload)} 字节")
        # hidapi 的 write 是阻塞调用；保留 timeout_ms 参数是为了与可注入
        # 传输接口一致。当前版本不对阻塞时长作虚假承诺。
        _validate_timeout(timeout_ms)
        device = self._require_device()
        wire = b"\x00" + payload
        try:
            written = device.write(wire)
        except Exception as exc:
            raise TransportDisconnected(
                f"写入 {self.device_name} 失败，设备可能已断开：{exc}"
            ) from exc
        if not isinstance(written, int) or written != len(wire):
            raise TransportDisconnected(f"写入 {self.device_name} 不完整：{written}/{len(wire)} 字节")

    def read_report(self, timeout_ms: int | None = None) -> bytes:
        """读取一条 64 字节报告；超时抛 :class:`TransportTimeout`。"""

        timeout = self.read_timeout_ms if timeout_ms is None else _validate_timeout(timeout_ms)
        if timeout is None:
            timeout = self.read_timeout_ms
        assert timeout is not None
        device = self._require_device()
        try:
            # hidapi 的 max_length 是缓冲区长度。Windows 可能在结果中包含
            # 报告 ID 0，因此多留一个字节再显式规范化。
            # open() 已设置非阻塞模式，因此 timeout=0 表示立即轮询。
            received = device.read(REPORT_SIZE + 1, timeout)
        except Exception as exc:
            raise TransportDisconnected(
                f"读取 {self.device_name} 失败，设备可能已断开：{exc}"
            ) from exc
        if not received:
            # hidapi 用空结果同时表示超时和断开，无法进一步区分。
            raise TransportTimeout(f"等待 {self.device_name} 报告超时（{timeout} ms）")
        data = bytes(received)
        if len(data) == REPORT_SIZE + 1 and data[0] == 0x00:
            data = data[1:]
        if len(data) != REPORT_SIZE:
            raise TransportError(
                f"{self.device_name} 返回了 {len(data)} 字节，期望 {REPORT_SIZE} 字节"
            )
        return data

