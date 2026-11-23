"""启动流程测试，用替身保证不枚举、不打开真实 USB。"""
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from stcforge.cli import main
from stcforge.ice import IceDisconnectedError, IceTimeoutError, ProtocolError, State

class CliTests(unittest.TestCase):
    def test_missing_image_is_rejected_before_usb_open(self):
        with mock.patch('stcforge.transport.HidTransport') as transport:
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(['gdbserver', '--usb']), 1)
            transport.assert_not_called()

    def test_usb_image_is_loaded_before_server_start(self):
        with tempfile.TemporaryDirectory(prefix='stcforge-cli-') as folder:
            image = Path(folder) / 'program.hex'
            image.write_text(':0200000400FFFB\n:0100000000FF\n:00000001FF\n', encoding='ascii')
            with mock.patch('stcforge.transport.HidTransport') as transport, \
                 mock.patch('stcforge.ice.IceSession') as session, \
                 mock.patch('stcforge.server.serve') as serve:
                snapshot = State(bytes(42) + bytes.fromhex('00FF0000'))
                session.return_value.initialize_debug.return_value = ('V4.0', snapshot)
                calls = mock.Mock()
                calls.attach_mock(transport.return_value.open, 'open')
                calls.attach_mock(session.return_value.initialize_debug, 'initialize_debug')
                calls.attach_mock(serve, 'serve')
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(main(['gdbserver', '--usb', '--image', str(image)]), 0)
                transport.return_value.open.assert_called_once()
                session.return_value.initialize_debug.assert_called_once_with()
                session.return_value.version.assert_not_called()
                session.return_value.read_state.assert_not_called()
                session.return_value.halt.assert_not_called()
                session.return_value.resume.assert_not_called()
                serve.assert_called_once()
                target = serve.call_args.args[0]
                self.assertEqual(target.image, {0xff0000: 0})
                self.assertIs(target.session, session.return_value)
                self.assertFalse(target.running)
                self.assertEqual(calls.mock_calls, [
                    mock.call.open(), mock.call.initialize_debug(),
                    mock.call.serve(target, '127.0.0.1', 3333, False),
                ])
                self.assertIn('V4.0', output.getvalue())
                self.assertIn('FF0000', output.getvalue())

    def test_failed_usb_initialization_closes_transport_without_starting_server(self):
        failures = (
            (ValueError('invalid startup options'), 1),
            (ProtocolError('invalid startup ACK or state'), 1),
            (IceTimeoutError('startup timeout'), 1),
            (IceDisconnectedError('startup disconnected'), 1),
            (KeyboardInterrupt(), 130),
        )
        with tempfile.TemporaryDirectory(prefix='stcforge-cli-') as folder:
            image = Path(folder) / 'program.hex'
            image.write_text(':0200000400FFFB\n:0100000000FF\n:00000001FF\n', encoding='ascii')
            for error, exit_code in failures:
                with self.subTest(error=type(error).__name__):
                    with mock.patch('stcforge.transport.HidTransport') as transport, \
                         mock.patch('stcforge.ice.IceSession') as session, \
                         mock.patch('stcforge.server.serve') as serve:
                        session.return_value.initialize_debug.side_effect = error
                        calls = mock.Mock()
                        calls.attach_mock(transport.return_value.open, 'open')
                        calls.attach_mock(session.return_value.initialize_debug, 'initialize_debug')
                        calls.attach_mock(transport.return_value.close, 'close')
                        with contextlib.redirect_stdout(io.StringIO()), \
                             contextlib.redirect_stderr(io.StringIO()):
                            self.assertEqual(
                                main(['gdbserver', '--usb', '--image', str(image)]), exit_code
                            )
                        self.assertEqual(calls.mock_calls, [
                            mock.call.open(), mock.call.initialize_debug(), mock.call.close(),
                        ])
                        session.return_value.initialize_debug.assert_called_once_with()
                        session.return_value.version.assert_not_called()
                        session.return_value.read_state.assert_not_called()
                        session.return_value.halt.assert_not_called()
                        session.return_value.resume.assert_not_called()
                        serve.assert_not_called()

    def test_usb_startup_wire_sequence_reaches_server_paused_without_extra_commands(self):
        version_request = bytes.fromhex('FF5A030000A4').ljust(64, b'\x00')
        start_request = bytes.fromhex('FF5A08020000FF0000009E').ljust(64, b'\x00')
        state_request = bytes.fromhex('FF5A030001A3').ljust(64, b'\x00')
        version_event = bytes.fromhex('07060056342E3004').ljust(64, b'\x00')
        ack = bytes.fromhex('0706000000000004').ljust(64, b'\x00')
        snapshot = bytes(42) + bytes.fromhex('00FF0000')
        state_reply = (bytes((48, 2)) + snapshot + bytes(((-2 - sum(snapshot)) & 0xff,))).ljust(64, b'\x00')
        replies = {version_request: version_event, start_request: ack, state_request: state_reply}
        pending = []
        timeline = []

        def write_report(report_bytes, *, timeout_ms=None):
            timeline.append(('write', report_bytes))
            pending.append(replies[report_bytes])

        def read_report(timeout_ms):
            from stcforge.transport import TransportTimeout
            if not pending:
                raise TransportTimeout('no pending reply')
            reply = pending.pop(0)
            timeline.append(('read', reply))
            return reply

        def serve_paused(target, host, port, once):
            self.assertFalse(target.running)
            self.assertEqual(target.image, {0xff0000: 0})
            timeline.append(('serve', target.running))

        with tempfile.TemporaryDirectory(prefix='stcforge-cli-') as folder:
            image = Path(folder) / 'program.hex'
            image.write_text(':0200000400FFFB\n:0100000000FF\n:00000001FF\n', encoding='ascii')
            with mock.patch('stcforge.transport.HidTransport') as transport, \
                 mock.patch('stcforge.server.serve', side_effect=serve_paused) as serve, \
                 mock.patch('time.sleep', side_effect=lambda seconds: timeline.append(('sleep', seconds))), \
                 contextlib.redirect_stdout(io.StringIO()):
                transport.return_value.write_report.side_effect = write_report
                transport.return_value.read_report.side_effect = read_report
                self.assertEqual(main(['gdbserver', '--usb', '--image', str(image)]), 0)
            serve.assert_called_once()
        self.assertEqual(timeline, [
            ('write', version_request), ('read', version_event),
            ('write', start_request), ('read', ack), ('sleep', 2.0),
            ('write', state_request), ('read', state_reply), ('serve', False),
        ])
        self.assertEqual(pending, [])

if __name__ == '__main__': unittest.main()
