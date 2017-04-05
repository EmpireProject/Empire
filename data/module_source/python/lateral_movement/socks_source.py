#from __future__ import unicode_literals, division

import select
import socket
import ssl
import struct
import sys
import threading


class MessageType(object):
    Control = 0
    Data = 1
    OpenChannel = 2
    CloseChannel = 3

    @classmethod
    def validate(cls, arg):
        if not isinstance(arg, int) or not MessageType.Control <= arg <= MessageType.CloseChannel:
            raise TypeError()
        return arg


class Message(object):
    HDR_STRUCT = b'!BHI'
    HDR_SIZE = struct.calcsize(HDR_STRUCT)

    def __init__(self, body, channel_id, msg_type=MessageType.Data):
        self.body = body
        self._channel_id = channel_id
        self.msg_type = msg_type

    @property
    def channel_id(self):
        return self._channel_id

    @classmethod
    def parse_hdr(cls, data):
        msg_type, channel_id, length = struct.unpack(cls.HDR_STRUCT, data[:struct.calcsize(cls.HDR_STRUCT)])
        MessageType.validate(msg_type)
        return msg_type, channel_id, length

    @classmethod
    def parse(cls, data):
        if len(data) < cls.HDR_SIZE:
            raise ValueError()
        msg_type, channel_id, length = cls.parse_hdr(data[:cls.HDR_SIZE])
        data = data[cls.HDR_SIZE:]
        if length != len(data):
            raise ValueError()
        MessageType.validate(msg_type)
        return Message(data, channel_id, msg_type=msg_type)

    def serialize(self):
        return struct.pack(self.HDR_STRUCT, self.msg_type, self.channel_id, len(self.body)) + self.body


class Channel(object):
    def __init__(self, channel_id):
        self._channel_id = channel_id
        self._client_end, self._tunnel_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.tx = 0
        self.rx = 0

    @property
    def tunnel_interface(self):
        return self._tunnel_end

    @property
    def client_interface(self):
        return self._client_end

    @property
    def channel_id(self):
        return self._channel_id

    def fileno(self):
        return self._client_end.fileno()

    def close(self):
        self._client_end.close()

    def send(self, data, flags=0):
        self._client_end.sendall(data, flags)
        self.tx += len(data)

    def recv(self, length):
        try:
            data = self._client_end.recv(length)
        except Exception:
            data = b''
        else:
            self.rx += len(data)
        return data


class Tunnel(object):
    def __init__(self, sock, open_channel_callback=None, close_channel_callback=None):
        self.transport = sock
        self.transport_lock = threading.Lock()
        self.channels = []
        self.closed_channels = {}

        if open_channel_callback is None:
            self.open_channel_callback = lambda x: None
        else:
            self.open_channel_callback = open_channel_callback

        if close_channel_callback is None:
            self.close_channel_callback = lambda x: None
        else:
            self.close_channel_callback = close_channel_callback

        self.monitor_thread = threading.Thread(target=self._monitor)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

    def wait(self):
        self.monitor_thread.join()

    @property
    def channel_id_map(self):
        return {x: y for x, y in self.channels}

    @property
    def id_channel_map(self):
        return {y: x for x, y in self.channels}

    def _close_channel_remote(self, channel_id):
        message = Message(b'', channel_id, msg_type=MessageType.CloseChannel)
        self.transport_lock.acquire()
        self.transport.sendall(message.serialize())
        self.transport_lock.release()

    def close_channel(self, channel_id, close_remote=False, exc=False):
        if channel_id in self.closed_channels:
            if close_remote:
                self._close_channel_remote(channel_id)
            return

        if channel_id not in self.id_channel_map:
            if exc:
                raise ValueError()
            else:
                return
        channel = self.id_channel_map[channel_id]
        try:
            self.channels.remove((channel, channel_id))
        except ValueError:
            return
        channel.close()
        channel.tunnel_interface.close()
        if close_remote:
            self._close_channel_remote(channel_id)
        self.close_channel_callback(channel)
        self.closed_channels[channel_id] = channel

    def close_tunnel(self):
        for channel, channel_id in self.channels:
            self.close_channel(channel_id, close_remote=True)
        self.transport.close()

    def _open_channel_remote(self, channel_id):
        message = Message(b'', channel_id, MessageType.OpenChannel)
        self.transport_lock.acquire()
        self.transport.sendall(message.serialize())
        self.transport_lock.release()

    def open_channel(self, channel_id, open_remote=False, exc=False):
        if channel_id in self.id_channel_map:
            if exc:
                raise ValueError()
            else:
                return self.id_channel_map[channel_id]
        channel = Channel(channel_id)
        self.channels.append((channel, channel_id))
        if open_remote:
            self._open_channel_remote(channel_id)
        self.open_channel_callback(channel)
        return channel

    def recv_message(self):
        data = b''
        while len(data) < Message.HDR_SIZE:
            _data = self.transport.recv(Message.HDR_SIZE - len(data))
            if not _data:
                break
            data += _data
        if len(data) != Message.HDR_SIZE:
            raise ValueError()
        msg_type, channel_id, length = Message.parse_hdr(data)

        chunks = []
        received = 0
        while received < length:
            _data = self.transport.recv(length - received)
            if not _data:
                break
            chunks.append(_data)
            received += len(_data)
        if received != length:
            raise ValueError()
        return Message(b''.join(chunks), channel_id, msg_type)

    def _monitor(self):
        while True:
            ignored_channels = []

            read_fds = [channel.tunnel_interface for channel, channel_id in self.channels] + [self.transport]

            try:
                r, _, _ = select.select(read_fds, [], [], 1)
            except Exception:
                continue

            if not r:
                continue

            if self.transport in r:
                try:
                    message = self.recv_message()
                except ValueError:
                    sys.exit(1)

                if message.msg_type == MessageType.CloseChannel:
                    self.close_channel(message.channel_id)
                    ignored_channels.append(message.channel_id)

                elif message.msg_type == MessageType.OpenChannel:
                    self.open_channel(message.channel_id)

                elif message.msg_type == MessageType.Data:
                    channel = self.id_channel_map.get(message.channel_id)
                    if channel is None:
                        self.close_channel(message.channel_id, close_remote=True)
                    else:
                        try:
                            channel.tunnel_interface.sendall(message.body)
                        except OSError as e:
                            self.close_channel(channel_id=message.channel_id, close_remote=True)

            else:
                tiface_channel_map = {channel.tunnel_interface: channel for (channel, channel_id) in self.channels}

                for tunnel_iface in r:
                    if tunnel_iface == self.transport:
                        continue

                    channel = tiface_channel_map.get(tunnel_iface)
                    if channel is None or channel.channel_id in ignored_channels:
                        continue

                    try:
                        data = tunnel_iface.recv(4096)
                    except Exception:
                        self.close_channel(channel.channel_id, close_remote=True)
                        continue
                    if not data:
                        self.close_channel(channel.channel_id, close_remote=True)
                        continue

                    message = Message(data, channel.channel_id, MessageType.Data)

                    try:
                        self.transport_lock.acquire()
                        self.transport.sendall(message.serialize())
                        self.transport_lock.release()
                    except:
                        return
        return

    def proxy_sock_channel(self, sock, channel, logger):

        def close_both():
            self.close_channel(channel.channel_id, close_remote=True)
            sock.close()

        while True:
            if (channel, channel.channel_id) not in self.channels:
                return

            readfds = [channel, sock]
            try:
                r, _, _ = select.select(readfds, [], [], 1)
            except Exception:
                return
            if not r:
                continue

            if channel in r:
                try:
                    data = channel.recv(4096)
                except Exception:
                    close_both()
                    return
                else:
                    if not data:
                        close_both()
                        return

                try:
                    sock.sendall(data)
                except Exception:
                    close_both()
                    return

            if sock in r:
                try:
                    data = sock.recv(4096)
                except Exception:
                    close_both()
                    return
                else:
                    if not data:
                        close_both()
                        return

                try:
                    channel.send(data)
                except Exception:
                    close_both()
                    return


class Socks5Proxy(object):
    @staticmethod
    def _remote_connect(remote_host, remote_port, sock, af=socket.AF_INET):
        remote_socket = socket.socket(af, socket.SOCK_STREAM)

        if af == socket.AF_INET:
            atyp = 1
            local_addr = ('0.0.0.0', 0)

        else:
            atyp = 4
            local_addr = ('::', 0)

        try:
            remote_socket.connect((remote_host, remote_port))
        except Exception:
            reply = struct.pack('BBBB', 0x05, 0x05, 0x00, atyp)
        else:
            local_addr = remote_socket.getsockname()[:2]
            reply = struct.pack('BBBB', 0x05, 0x00, 0x00, atyp)

        reply += socket.inet_pton(af, local_addr[0]) + struct.pack('!H', local_addr[1])
        sock.send(reply)

        return remote_socket

    @classmethod
    def new_connect(cls, sock):
        sock.recv(4096)
        sock.sendall(struct.pack('BB', 0x05, 0x00))

        request_data = sock.recv(4096)
        if len(request_data) >= 10:
            ver, cmd, rsv, atyp = struct.unpack('BBBB', request_data[:4])
            if ver != 0x05 or cmd != 0x01:
                sock.sendall(struct.pack('BBBB', 0x05, 0x01, 0x00, 0x00))
                sock.close()
                raise ValueError()
        else:
            sock.sendall(struct.pack('BBBB', 0x05, 0x01, 0x00, 0x00))
            sock.close()
            raise ValueError()

        if atyp == 1:
            addr_type = socket.AF_INET
            addr = socket.inet_ntop(socket.AF_INET, request_data[4:8])
            port, = struct.unpack('!H', request_data[8:10])
        elif atyp == 3:
            addr_type = socket.AF_INET
            length, = struct.unpack('B', request_data[4:5])
            addr = request_data[5:5 + length].decode()
            port, = struct.unpack('!H', request_data[length + 5:length + 5 + 2])
        elif atyp == 4:
            addr_type = socket.AF_INET6
            addr = socket.inet_ntop(socket.AF_INET6, request_data[4:20])
            port, = struct.unpack('!H', request_data[20:22])
        else:
            sock.sendall(struct.pack('BBBB', 0x05, 0x08, 0x00, 0x00))
            sock.close()
            raise ValueError()

        host = (addr, port)
        remote_sock = cls._remote_connect(addr, port, sock, af=addr_type)
        return remote_sock, host


class Relay(object):
    def __init__(self, connect_host, connect_port, no_ssl=False):
        self.no_ssl = no_ssl
        self.connect_server = (connect_host, connect_port)
        self.tunnel = None
        self.tunnel_sock = socket.socket()
        if not no_ssl:
            try:
                self.tunnel_sock = ssl.wrap_socket(self.tunnel_sock)
            except ssl.SSLError as e:
                sys.exit(-1)

    def _handle_channel(self, channel):
        sock = None

        try:
            sock, addr = Socks5Proxy.new_connect(channel.client_interface)
        except ValueError:
            self.tunnel.close_channel(channel.channel_id, close_remote=True)
            return
        except Exception:
            self.tunnel.close_channel(channel.channel_id, close_remote=True)
            try:
                if isinstance(sock, socket.socket):
                    sock.close()
            except:
                pass
            return
        self.tunnel.proxy_sock_channel(sock, channel, None)

    def open_channel_callback(self, channel):
        t = threading.Thread(target=self._handle_channel, args=(channel,))
        t.daemon = True
        t.start()

    def run(self):
        try:
            self.tunnel_sock.connect(self.connect_server)
        except Exception:
            return

        self.tunnel = Tunnel(self.tunnel_sock, open_channel_callback=self.open_channel_callback)
        self.tunnel.wait()


relay = Relay('${host}', ${port}, no_ssl=${no_ssl})
relay.run()
