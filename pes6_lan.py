#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PES6 LAN 0.2 -- one-file PC LAN server; Stadium chat disabled by default.

تشغيله على Windows 11 فقط، ولا يحتاج XP إلى Python.
تحديث 0.2: تعطيل دردشة Stadium/Match مع إبقاء دردشة اللوبي والغرفة.
للتحديث: استبدل الملف على الهوست، أعد تشغيله، وأعد دخول Network وأنشئ غرفة جديدة.
لا تعِد تشغيل CMD على XP إذا لم يتغير عنوان الهوست أو منفذ UDP.
1) ثبّت Python 3 على الهوست فقط، ثم شغّل: py pes6_lan.py
2) اختر عنوان IPv4 الخاص بشبكة اللعب ووافق على إعداد الهوست.
3) انقل PES6_XP_CONNECT.cmd إلى XP وشغّله بحساب مسؤول مرة واحدة.
4) UDP في اللعبة = GAME_UDP_PORT أدناه (5739 افتراضياً)، و UPnP معطّل.
5) Network -> أي كلمة مرور غير فارغة -> اختر Player -> PES6 LAN -> LAN.
   أنشئ غرفة، ادخل إليها بالجهاز الثاني، ثم Participate / Start match.

كل الحسابات والغرف والإعدادات في RAM وتختفي بإغلاق السيرفر. لا تسجيل ولا DB.
الملف المساعد يعدّل hosts ويضيف استثناءات LAN محدودة؛ لا يعطّل جدار الحماية.
لا إنترنت مطلوب أثناء اللعب، ولا Hamachi أو Docker أو pip على أي جهاز.
يحتاج الجهازان إلى نسختين متوافقتين من اللعبة والباتش وبيانات الفرق.
هذا اختصار لوظائف LAN، وليس بديلاً كاملًا لكل خدمات Fiveserver.
لم يُختبر بمباراة حقيقية بين Windows 11 و XP؛ راجع حدود الاختبار في README.

Optional commands (on the host only):
  py pes6_lan.py --ip 192.168.1.10
  py pes6_lan.py --udp-port 5739
  py pes6_lan.py --no-setup          # do not change this PC's hosts/firewall
  py pes6_lan.py --undo             # undo this PC's setup; stop server first
  py pes6_lan.py --debug            # packet IDs/lengths, never passwords
  py pes6_lan.py --self-test        # internal checks; no configuration changes
XP undo: PES6_XP_CONNECT.cmd --undo

Based on the PES6 and shared PES5 wire protocol in juce/fiveserver:
https://github.com/juce/fiveserver
Upstream revision: 83d191f9a541a31615fa5a2e4260941881b318b7
Protocol analysis and original implementation: juce, reddwarf.
BSD-2-Clause license; original copyright and conditions follow at end of file.
"""

import argparse
import asyncio
import ctypes
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone

# The only setting normally worth changing. Use this UDP port in BOTH games.
GAME_UDP_PORT = 5739
# Keyboard-friendly policy. False restores the previous chat behaviour.
# This changes advertised chat settings; it does NOT remap client keys.
DISABLE_STADIUM_CHAT = True
SERVER_NAME = "PES6 LAN"
GATEWAY_NAMES = ("pes6gate-ec.winning-eleven.net", "pes6online.got-game.org")
STUN_NAMES = ("we9stun.winning-eleven.net", "stun6server.got-game.org")
TCP_PORTS = {"news": 10881, "main": 20200, "menu": 20201, "login": 20202}
STUN_PORTS = (3478, 3479)
MAX_ACCOUNTS, MAX_CONNECTIONS, MAX_ROOMS = 64, 96, 32
MAX_PENDING_BYTES = 512 * 1024
ZERO = b"\0" * 4
KEY = b"\xa6\x77\x95\x7c"
PRIVATE_NETS = tuple(ipaddress.ip_network(s) for s in
                     ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                      "169.254.0.0/16", "127.0.0.0/8"))


def log(message):
    print(time.strftime("[%H:%M:%S] ") + str(message), flush=True)


def pad(value, size):
    if isinstance(value, str):
        value = value.encode("utf-8", "replace")
    return bytes(value)[:size].ljust(size, b"\0")


def cstr(value):
    return bytes(value).split(b"\0", 1)[0]


def i32(value):
    return struct.pack("!i", value)


def u32(value):
    return struct.pack("!I", value)


def integer(data, offset=0):
    return struct.unpack_from("!i", data, offset)[0]


def xor(data):
    # XOR position resets at each complete PES packet, not each TCP recv().
    return bytes(b ^ KEY[n & 3] for n, b in enumerate(data))


def make_packet(pid, data=b"", count=1):
    head = struct.pack("!HHI", pid, len(data), count)
    return xor(head + hashlib.md5(head + data).digest() + data)


def parse_packet(wire):
    plain = xor(wire)
    if len(plain) < 24:
        raise ValueError("short PES packet")
    pid, length, count = struct.unpack("!HHI", plain[:8])
    if len(plain) != length + 24:
        raise ValueError("wrong PES packet length")
    if hashlib.md5(plain[:8] + plain[24:]).digest() != plain[8:24]:
        raise ValueError("wrong PES packet MD5")
    return pid, plain[24:], count


def is_lan(ip):
    try:
        addr = ipaddress.IPv4Address(ip)
        return not (addr.is_unspecified or addr.is_multicast) and any(
            addr in net for net in PRIVATE_NETS)
    except ipaddress.AddressValueError:
        return False


@dataclass(eq=False)
class Profile:
    id: int = 0
    name: bytes = b""
    comment: bytes = b""
    settings: tuple = ()


@dataclass(eq=False)
class Account:
    profiles: list
    lobby: object = None


@dataclass(eq=False)
class Room:
    id: int
    name: bytes
    password: bytes = b""
    locked: bool = False
    players: list = field(default_factory=list)
    participants: list = field(default_factory=list)
    owner: object = None
    starter: object = None
    phase: int = 1
    ready: set = field(default_factory=set)
    sides: dict = field(default_factory=dict)
    captains: dict = field(default_factory=dict)
    teams: list = field(default_factory=lambda: [65535, 65535])
    settings: bytes = b""
    match_state: int = 0
    clock: int = 0
    goals: list = field(default_factory=lambda: [[0] * 5, [0] * 5])

    def part(self, player):
        return self.participants.index(player) if player in self.participants else 255

    def participation(self):
        return b"".join(i32(p.profile.id) + bytes((i, self.part(p)))
                        for i, p in enumerate(self.players)) + (
                            b"\0\0\0\0\0\xff" * (4 - len(self.players)))

    def info(self):
        people = b"".join(i32(p.profile.id) + bytes((
            int(p is self.owner), int(p is self.starter),
            self.sides.get(p.profile.id, 255), p.spectator, i, self.part(p)))
            for i, p in enumerate(self.players))
        people += b"\0\0\0\0\0\0\xff\0\0\xff" * (4 - len(self.players))
        scores = b"".join(struct.pack("!H", team) + bytes(goals)
                           for team, goals in zip(self.teams, self.goals))
        return (i32(self.id) + bytes((self.phase, self.match_state)) +
                pad(self.name, 64) + bytes((self.clock,)) + people + scores +
                bytes((0, int(self.locked))) +
                # Competition flag, match-chat mode, two reserved bytes.
                bytes((0, 0 if DISABLE_STADIUM_CHAT else 2, 0, 0)))

    def tell(self, pid, data, exclude=None):
        for player in tuple(self.players):
            if player is not exclude:
                player.send(pid, data)

    def reset_match(self):
        self.match_state = self.clock = 0
        self.goals = [[0] * 5, [0] * 5]
        self.ready.clear()


class World:
    def __init__(self, ip, udp_port=GAME_UDP_PORT, debug=False):
        self.ip, self.udp_port, self.debug = ip, udp_port, debug
        self.accounts, self.profiles, self.players, self.rooms = {}, {}, {}, {}
        self.connections = set()
        self.next_profile = self.next_room = 1
        self.servers, self.udp_transports = [], []
        self.shutting_down = False

    def new_profile(self, name):
        p = Profile(self.next_profile, cstr(name)[:47])
        self.next_profile += 1
        self.profiles[p.id] = p
        return p

    def account(self, ip, opaque_token):
        # Fiveserver identifies credentials using these 16 ciphertext bytes.
        # LAN auto-registration needs neither their plaintext nor Blowfish.
        # Include source IP so identical passwords on two PCs stay distinct.
        key = (ip, opaque_token)
        if key not in self.accounts:
            if len(self.accounts) >= MAX_ACCOUNTS:
                raise ValueError("64 temporary accounts reached; restart the server")
            ordinal = len(self.accounts) + 1
            name = ("Player%d" % ordinal).encode()
            while any(p.name.lower() == name.lower() for p in self.profiles.values()):
                ordinal += 1
                name = ("Player%d" % ordinal).encode()
            p = self.new_profile(name)
            self.accounts[key] = Account([p, Profile(), Profile()])
        return self.accounts[key]

    def tell(self, pid, data):
        if not self.shutting_down:
            for player in tuple(self.players.values()):
                player.send(pid, data)

    def room_update(self, room):
        self.tell(0x4306, room.info())

    def player_update(self, player):
        self.tell(0x4222, player.player_info())

    async def accept(self, reader, writer, kind):
        peer = writer.get_extra_info("peername")
        if (not peer or not is_lan(peer[0]) or
                len(self.connections) >= MAX_CONNECTIONS):
            writer.close()
            return
        conn = Connection(self, writer, peer[0], kind)
        self.connections.add(conn)
        sock = writer.get_extra_info("socket")
        if sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        log("TCP %s <- %s" % (kind, peer[0]))
        try:
            while not writer.is_closing():
                # readexactly handles both fragmented and coalesced TCP frames.
                head = await asyncio.wait_for(reader.readexactly(8),
                                               1800 if conn.account else 60)
                length = struct.unpack("!H", xor(head)[2:4])[0]
                tail = await asyncio.wait_for(reader.readexactly(16 + length), 30)
                pid, data, _ = parse_packet(head + tail)
                conn.receive(pid, data)
                await asyncio.wait_for(writer.drain(), 15)
        except (asyncio.IncompleteReadError, ConnectionError, asyncio.TimeoutError):
            pass
        except (ValueError, IndexError, struct.error) as exc:
            log("Rejected packet from %s (%s): %s" % (peer[0], kind, exc))
        except Exception:
            log("Unexpected protocol error; please save this traceback:")
            traceback.print_exc()
        finally:
            conn.leave_lobby()
            self.connections.discard(conn)
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 2)
            except (OSError, asyncio.TimeoutError):
                pass
            log("TCP %s disconnected: %s" % (kind, peer[0]))

    async def open(self):
        # Open all listeners before claiming READY. A conflict is fatal.
        try:
            for kind, port in TCP_PORTS.items():
                server = await asyncio.start_server(
                    lambda r, w, k=kind: self.accept(r, w, k), "0.0.0.0", port,
                    limit=131072)
                self.servers.append(server)
            loop = asyncio.get_running_loop()
            for port in STUN_PORTS:
                transport, _ = await loop.create_datagram_endpoint(
                    lambda p=port: StunServer(self, p),
                    local_addr=(self.ip, port), family=socket.AF_INET)
                self.udp_transports.append(transport)
        except OSError:
            await self.close()
            raise

    async def close(self):
        self.shutting_down = True
        for server in self.servers:
            server.close()
        for server in self.servers:
            await server.wait_closed()
        for transport in self.udp_transports:
            transport.close()
        for conn in tuple(self.connections):
            conn.writer.close()
        self.servers.clear()
        self.udp_transports.clear()


class Connection:
    def __init__(self, world, writer, ip, kind):
        self.world, self.writer, self.ip, self.kind = world, writer, ip, kind
        self.count = 1
        self.account = self.profile = self.room = None
        self.in_lobby = False
        self.spectator = 0
        self.cancelled_until = 0
        self.udp_port = world.udp_port
        self.peer_ip = world.ip if ip.startswith("127.") else ip
        self.upload_settings = []
        self.window, self.requests = time.monotonic(), 0

    def send(self, pid, data=ZERO):
        if self.writer.is_closing():
            return
        if self.writer.transport.get_write_buffer_size() > MAX_PENDING_BYTES:
            self.writer.close()
            return
        if self.world.debug:
            log("  %s -> %04x (%d bytes)" % (self.kind, pid, len(data)))
        self.writer.write(make_packet(pid, data, self.count))
        self.count = (self.count + 1) & 0xffffffff

    def player_info(self):
        p = self.profile
        rid = self.room.id if self.room else 0
        # PES6 player-list record, exactly 127 bytes.
        return (i32(p.id) + pad(p.name, 48) + ZERO + b"\0" * 48 + b"\0\0" +
                i32(rid) + ZERO + b"\0" * 10 + b"\0" * 3)

    def profile_info(self, p):
        if self.kind == "menu":
            # Upstream PES6 NetworkMenuService inherits this PES5 layout.
            return (i32(p.id) + pad(p.name, 16) + b"\0" * 37)
        # PES6 MainService layout. All permanent statistics are intentionally 0.
        return (i32(p.id) + pad(p.name, 48) + ZERO + pad("LAN", 48) +
                b"\1\0" + ZERO + b"\0" * 16 + b"\0" * 8 +
                pad(p.comment or b"Local game - no permanent stats", 256) +
                ZERO + b"\0" * 14 + b"\xff\xff" * 5)

    def stun_info(self, other, prefix=32):
        # Both advertised endpoints are the real LAN address, not a WAN/VPN IP.
        address = pad(other.peer_ip, 16) + struct.pack("!H", other.udp_port)
        return (b"\0" * prefix + address * 2 + i32(other.profile.id) +
                b"\0\0" + bytes((other.room.part(other) if other.room else 255,)))

    def leave_room(self, reply=False):
        room = self.room
        if room:
            if self in room.participants:
                room.participants.remove(self)
            room.ready.discard(self)
            room.sides.pop(self.profile.id, None)
            if self in room.players:
                room.players.remove(self)
            if room.owner is self:
                room.owner = room.players[0] if room.players else None
            if room.starter is self:
                room.starter = room.owner
            self.room = None
            self.spectator = 0
            self.world.room_update(room)
            self.world.player_update(self)
            room.tell(0x4365, room.participation())
        if reply:
            self.send(0x432b)
        if room and not room.players:
            self.world.rooms.pop(room.id, None)
            self.world.tell(0x4305, i32(room.id))
            log("Room %d closed" % room.id)

    def leave_lobby(self):
        if not self.in_lobby:
            return
        self.leave_room()
        self.in_lobby = False
        if self.world.players.get(self.profile.id) is self:
            del self.world.players[self.profile.id]
            self.world.tell(0x4221, i32(self.profile.id))
        if self.account and self.account.lobby is self:
            self.account.lobby = None

    def receive(self, pid, data):
        if time.monotonic() - self.window >= 1:
            self.window, self.requests = time.monotonic(), 0
        self.requests += 1
        if self.requests > 600:
            raise ValueError("too many requests per second")
        if self.world.debug:
            log("  %s <- %04x (%d bytes)" % (self.kind, pid, len(data)))
        if pid == 0x0005:
            self.send(pid, data)  # rebuild the checksum with OUR sequence number
            return
        if pid == 0x0003:
            self.leave_lobby()
            return
        if self.kind == "news":
            self.news(pid, data)
            return
        if pid == 0x3001:
            self.send(0x3002, b"\0" * 16)
            return
        if pid == 0x3003:
            if len(data) < 48 or len(data) % 8:
                raise ValueError("invalid authentication packet")
            if self.in_lobby:
                raise ValueError("authentication repeated inside a lobby")
            self.account = self.world.account(self.ip, data[32:48])
            self.profile = self.account.profiles[0]
            self.send(0x3004)
            return
        if self.account is None:
            raise ValueError("authenticate before using game services")
        if self.common(pid, data):
            return
        if not self.in_lobby:
            if pid == 0x4a00:
                self.send(0x4a01, b"\0\0\0\1")
                return
            raise ValueError("join the LAN lobby before using room services")
        self.lobby_packet(pid, data)

    def news(self, pid, data):
        if pid == 0x2008:
            self.send(0x2009)
            text = (b"Local PES6 game. No registration needed.\r\n"
                    b"Choose a Player profile, then the LAN lobby.\r\n"
                    b"All data is temporary.\r\n\r\n"
                    b"Protocol credits: juce and reddwarf.")
            date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            self.send(0x200a, ZERO + b"\1\1" + pad(date, 19) +
                      pad(SERVER_NAME, 64) + text)
            self.send(0x200b, b"")
        elif pid == 0x2005:
            servers = ((2, "LOGIN", TCP_PORTS["login"], 0),
                       (3, SERVER_NAME, TCP_PORTS["main"],
                        max(0, len(self.world.players) - 1)),
                       (8, "NETWORK_MENU", TCP_PORTS["menu"], 0))
            payload = b"".join(struct.pack("!ii", -1, typ) + pad(name, 32) +
                               pad(self.world.ip, 15) +
                               struct.pack("!HHH", port, users, typ)
                               for typ, name, port, users in servers)
            self.send(0x2002)
            self.send(0x2003, payload)
            self.send(0x2004)
        elif pid == 0x2006:
            self.send(0x2007, u32(int(time.time())))
        elif pid == 0x2200:
            self.send(0x2201)
            self.send(0x2203)

    def common(self, pid, data):
        if pid == 0x3010:
            entries = []
            for index, p in enumerate(self.account.profiles):
                # Only LoginService overrides the profile-list layout upstream.
                entry = bytes((index,)) + i32(p.id) + pad(
                    p.name, 48 if self.kind == "login" else 16)
                entry += ZERO + b"\0" + ZERO
                if self.kind == "login":
                    entry += b"\0\0"  # rating
                entries.append(entry + b"\0\0")  # matches
            self.send(0x3012, ZERO + b"".join(entries))
        elif pid == 0x3020:
            index, name = data[0], cstr(data[1:])[:47]
            if index > 2 or not name or self.account.lobby:
                self.send(0x3022, u32(0xfffffefc))
            elif any(p.name.lower() == name.lower() and
                     p is not self.account.profiles[index]
                     for p in self.world.profiles.values()):
                self.send(0x3022, u32(0xfffffefc))
            else:
                p = self.account.profiles[index]
                if not p.id:
                    p = self.world.new_profile(name)
                    self.account.profiles[index] = p
                else:
                    p.name = name
                self.send(0x3022)
        elif pid == 0x3030:
            index = data[0]
            if index > 2 or self.account.lobby:
                self.send(0x3032, u32(0xffffffff))
            else:
                p = self.account.profiles[index]
                self.world.profiles.pop(p.id, None)
                self.account.profiles[index] = Profile()
                self.send(0x3032)
        elif pid == 0x3040:
            if self.in_lobby:
                raise ValueError("cannot change profile while in a lobby")
            p = next((p for p in self.account.profiles
                      if p.id and p.id == integer(data)), None)
            if p:
                self.profile = p
                self.send(0x3042, ZERO + pad(p.name, 16) + b"\0" * (0x18e - 20))
            else:
                self.send(0x3041)
        elif pid == 0x4100:
            index = data[0]
            if index > 2 or not self.account.profiles[index].id or self.in_lobby:
                raise ValueError("invalid selected profile")
            self.profile = self.account.profiles[index]
            self.send(0x4101, ZERO + i32(self.profile.id) +
                      b"\xff" * 7 + b"\x80" + b"\xff" * 15 + b"\xc0" +
                      b"\2" * 7 + b"\1\0")
            self.send(0x4103, ZERO + self.profile_info(self.profile))
        elif pid == 0x4102:
            p = self.world.profiles.get(integer(data))
            self.send(0x4103, ZERO + self.profile_info(p) if p else b"")
        elif pid == 0x4110:
            if self.kind == "menu":
                self.send(0x4112)  # inherited favourite-team ACK, no persistent stats
            else:
                self.profile.comment = cstr(data)[:255]
                self.send(0x4111)
        elif pid == 0x4200:
            self.send(0x4201, b"\0\1\x20" + pad("LAN", 32) +
                      struct.pack("!H", len(self.world.players)))
        elif pid == 0x4202:
            if len(data) < 39 or data[0] != 0 or not self.profile.id:
                self.send(0x4203, b"\0\0\0\1")
                return True
            self.leave_lobby()
            old = self.account.lobby
            if old and old is not self:
                old.leave_lobby()
                old.writer.close()
            # No NAT within the supported topology. Prefer the local game port.
            external = struct.unpack_from("!H", data, 17)[0]
            local = struct.unpack_from("!H", data, 35)[0]
            self.udp_port = local or external or self.world.udp_port
            self.in_lobby, self.account.lobby = True, self
            self.world.players[self.profile.id] = self
            self.send(0x4203)
            self.world.tell(0x4220, self.player_info())
            log("%s in LAN lobby, game UDP %s:%d" % (
                self.profile.name.decode("utf-8", "replace"), self.peer_ip, self.udp_port))
            if self.udp_port != self.world.udp_port:
                log("NOTE: game UDP differs from setup; allow UDP %d in that PC's firewall"
                    % self.udp_port)
        elif pid == 0x308a:
            if len(self.profile.settings) == 2:
                self.send(0x3087, ZERO + i32(self.profile.id))
                for chunk in self.profile.settings:
                    self.send(0x3088, chunk)
                self.send(0x3089, b"")
            else:
                self.send(0x3087, u32(0xfffffedd))
        elif pid == 0x3087:
            self.upload_settings = []
        elif pid == 0x3088:
            if len(self.upload_settings) < 2:
                self.upload_settings.append(bytes(data))
        elif pid == 0x3089:
            if len(self.upload_settings) == 2:
                self.profile.settings = tuple(self.upload_settings)
            self.upload_settings = []
            self.send(0x308b)
        elif pid == 0x3070:
            if self.kind == "login":
                self.send(0x3071)
                self.send(0x3073)
            else:
                self.send(0x3072)  # inherited PES5 empty-history layout
        elif pid in (0x3120, 0x4580, 0x4600, 0x4780):
            self.send(pid + 1)
            self.send(pid + 3, b"" if pid == 0x3120 else ZERO)
        elif pid == 0x3080:
            self.send(0x3082)
            self.send(0x3086, b"")
        elif pid == 0x3050:
            self.send(0x3052, b"\0" * 0x47)
        elif pid == 0x3060:
            self.send(0x3062, b"\0")
        elif pid in (0x3090, 0x3100):
            self.send(pid + 1)
        elif pid == 0x4114:
            self.send(0x4116)
        elif pid == 0x6020:
            self.send(0x6021, b"")  # quick matchmaking not implemented
        elif pid < 0x4200:
            log("Unimplemented %s packet %04x; upstream-style empty ACK" % (self.kind, pid))
            self.send((pid + 1) & 0xffff)
        else:
            return False
        return True

    def join_room(self, room):
        if self.room and self.room is not room:
            raise ValueError("leave the current room before entering another")
        if self not in room.players:
            self.room = room
            self.spectator = 0
            self.cancelled_until = 0
            if not room.players:
                room.owner = self
            room.players.append(self)
        self.world.room_update(room)
        self.world.player_update(self)

    def notify_endpoints(self, room):
        room.tell(0x4330, self.stun_info(self, 36), exclude=self)
        self.send(0x4346, b"")
        for other in room.players:
            if other is not self:
                self.send(0x4347, self.stun_info(other))
        self.send(0x4348, b"")

    def advance_if_ready(self, room):
        if (2 <= room.phase <= 6 and room.participants and
                all(p in room.ready for p in room.participants)):
            room.phase += 1
            room.ready.clear()
            room.tell(0x4344, bytes((room.phase,)))
            self.world.room_update(room)

    def lobby_packet(self, pid, data):
        room, world = self.room, self.world
        if pid == 0x4210:
            self.send(0x4211)
            for player in tuple(world.players.values()):
                self.send(0x4212, player.player_info())
            self.send(0x4213)
            return
        if pid == 0x4300:
            self.send(0x4301)
            for entry in tuple(world.rooms.values()):
                self.send(0x4302, entry.info())
            self.send(0x4303)
            return
        if pid == 0x4310:
            if len(data) < 65:
                raise ValueError("short create-room packet")
            name = cstr(data[:64])
            if room or not name or len(world.rooms) >= MAX_ROOMS:
                self.send(0x4311, u32(0xffffffff))
            elif any(r.name == name for r in world.rooms.values()):
                self.send(0x4311, u32(0xffffff10))
            else:
                room = Room(world.next_room, name, cstr(data[65:80]), data[64] == 1)
                world.next_room += 1
                world.rooms[room.id] = room
                self.join_room(room)
                self.send(0x4311)
                log("Room %d created: %s" % (room.id, name.decode("utf-8", "replace")))
            return
        if pid == 0x4320:
            chosen = world.rooms.get(integer(data))
            if chosen is None or (room and room is not chosen):
                self.send(0x4321, b"\0\0\0\1")
            elif chosen.locked and cstr(data[4:19]) != chosen.password:
                self.send(0x4321, u32(0xfffffdda))
            elif self not in chosen.players and len(chosen.players) >= 4:
                self.send(0x4321, u32(0xfffffdbb))
            else:
                self.join_room(chosen)
                self.send(0x4321, ZERO + chosen.settings[:1])
                self.notify_endpoints(chosen)
            return
        if pid == 0x432a:
            self.leave_room(reply=True)
            return
        if pid == 0x4325:
            self.leave_room()
            self.send(0x4326)
            return
        if pid == 0x4345:
            chosen = world.rooms.get(integer(data))
            self.send(0x4346, b"")
            if chosen:
                for other in chosen.players:
                    self.send(0x4347, self.stun_info(other))
                if self.room is chosen:
                    chosen.tell(0x4330, self.stun_info(self, 36), exclude=self)
            self.send(0x4348, b"")
            return
        if pid == 0x4b00:
            other = world.players.get(integer(data))
            if other:
                endpoint = pad(other.peer_ip, 16) + struct.pack("!H", other.udp_port)
                self.send(0x4b01, ZERO + endpoint * 2 + i32(other.profile.id))
            else:
                self.send(0x4b01, u32(0xffffffff))
            return
        if pid == 0x4400:
            if len(data) < 10:
                raise ValueError("short chat packet")
            typ = data[:2]
            # Keep lobby/private/room chat. Do not echo Stadium/Match typing.
            # Filtering messages alone cannot change a client UI focus;
            # the room and match-settings flags below carry that policy.
            if DISABLE_STADIUM_CHAT and typ in (b"\1\5", b"\1\7"):
                return
            message = (typ + data[2:6] + i32(self.profile.id) +
                       pad(self.profile.name, 48) + cstr(data[10:])[:126] + b"\0\0")
            if typ == b"\0\1":
                world.tell(0x4402, message)
            elif typ in (b"\1\x08", b"\1\5", b"\1\7") and room:
                room.tell(0x4402, message)
            elif typ == b"\0\2":
                other = world.players.get(integer(data, 6))
                if other:
                    other.send(0x4402, message)
                    if other is not self:
                        self.send(0x4402, message)
            return
        if pid == 0x4a00:
            self.send(0x4a01, b"\0\0\0\1")
            self.leave_lobby()
            return
        if not room:
            self.send((pid + 1) & 0xffff, u32(0xffffffff))
            return
        if pid == 0x4349:
            new_owner = world.players.get(integer(data))
            if room.owner is not self or new_owner not in room.players:
                self.send(0x434a, u32(0xffffffff))
            else:
                room.owner = new_owner
                world.room_update(room)
                self.send(0x434a)
        elif pid == 0x434d:
            if len(data) < 65:
                raise ValueError("short room-name packet")
            name = cstr(data[:64])
            if room.owner is not self or not name or any(
                    r is not room and r.name == name for r in world.rooms.values()):
                self.send(0x434e, u32(0xffffffff))
            else:
                room.name, room.locked = name, data[64] == 1
                room.password = cstr(data[65:80])
                world.room_update(room)
                self.send(0x434e)
        elif pid == 0x4363:
            participating, status = data[0] == 1, ZERO
            if participating:
                if time.monotonic() < self.cancelled_until:
                    status = u32(0xfffffdb6)
                elif self not in room.participants:
                    if len(room.participants) == 4:
                        status = u32(0xfffffdbb)
                    else:
                        room.participants.append(self)
                        self.spectator = 0
            elif self in room.participants:
                room.participants.remove(self)
                room.ready.discard(self)
            room.tell(0x4365, room.participation())
            self.send(0x4364, status + bytes((int(participating), room.part(self))))
        elif pid == 0x4380:
            other = world.players.get(integer(data))
            if room.owner is not self or other not in room.players:
                self.send(0x4381, u32(0xffffffff))
            else:
                if other in room.participants:
                    room.participants.remove(other)
                room.ready.discard(other)
                other.cancelled_until = time.monotonic() + 10
                room.tell(0x4365, room.participation())
                self.send(0x4381)
        elif pid == 0x4366:
            self.spectator = 1
            self.send(0x4367)
        elif pid == 0x4360:
            if len(room.participants) < 2 or self not in room.players:
                self.send(0x4361, b"\0\0\0\1")
            else:
                room.reset_match()
                room.sides.clear()
                room.captains.clear()
                room.teams = [65535, 65535]
                room.starter, room.phase = self, 2
                payload = pad(b"\2" + b"".join(i32(p.profile.id)
                                              for p in room.participants), 37)
                room.tell(0x4362, payload)
                world.room_update(room)
                self.send(0x4361)
        elif pid == 0x436f:
            choice = data[0]
            if 2 <= room.phase <= 6:
                if self in room.participants:
                    if choice == 1:
                        room.ready.add(self)  # duplicate Ready must not advance twice
                    elif choice == 0:
                        room.ready.discard(self)
            elif room.phase > 6:
                if choice == 0:
                    if self in room.participants:
                        room.participants.remove(self)
                    room.phase = 10 if room.participants else 1
                    if not room.participants:
                        room.reset_match()
                elif choice in (3, 4):
                    room.phase = 4 if choice == 3 else 6
                    room.reset_match()
                    if choice == 3:
                        room.teams = [65535, 65535]
                world.room_update(room)
            room.tell(0x4371, i32(self.profile.id) + data[:1], exclude=self)
            self.send(0x4370)
            self.advance_if_ready(room)
        elif pid == 0x4369:
            if len(data) < 32:
                raise ValueError("short side-selection packet")
            sides, captains = {}, {}
            for pos in range(4):
                profile_id, side = integer(data, pos * 8), data[pos * 8 + 4]
                if not profile_id:
                    continue
                if side not in (0, 1) or not any(
                        p.profile.id == profile_id for p in room.players):
                    raise ValueError("invalid side-selection player")
                sides[profile_id] = side
                if pos < 2:
                    captains[side] = profile_id
            room.sides, room.captains = sides, captains
            self.send(0x436a)
            room.tell(0x436b, b"\0" + data)
            world.room_update(room)
        elif pid == 0x436c:
            if len(data) < 12:
                raise ValueError("short match-settings packet")
            settings = bytes(data)
            if DISABLE_STADIUM_CHAT:
                # MatchSettings byte 3 is chat_during_gameplay upstream.
                # Change ONLY this byte; preserve time, teams and extra data.
                settings = settings[:3] + b"\0" + settings[4:]
            room.settings = settings
            self.send(0x436d)
            # Include the sender: both games must use identical settings.
            room.tell(0x436e, settings)
            world.room_update(room)
        elif pid == 0x4350:
            room.tell(0x4350, data, exclude=self)
        elif pid == 0x4351:
            for other in room.players:
                if other not in room.participants:
                    other.send(0x4351, data)
            self.send(0x4352)
        elif pid == 0x4373:
            team = struct.unpack_from("!H", data)[0]
            for side, captain in room.captains.items():
                if self.profile.id == captain:
                    room.teams[side] = team
            self.send(0x4374)
            world.room_update(room)
        elif pid == 0x4377:
            state = data[0]
            if state > 10:
                raise ValueError("invalid match state")
            if state == 1 and room.match_state != 1:
                room.reset_match()
                log("Match started in room %d" % room.id)
            room.match_state = state
            if state == 10:
                room.phase = 8
                log("Match finished in room %d: %d - %d" % (
                    room.id, sum(room.goals[0]), sum(room.goals[1])))
            world.room_update(room)
            self.send(0x4378)
        elif pid == 0x4375:
            side = 0 if data[0] == 0 else 1
            period = {1: 0, 3: 1, 5: 2, 7: 3, 9: 4}.get(room.match_state)
            if period is not None:
                room.goals[side][period] = min(255, room.goals[side][period] + 1)
            self.send(0x4376)
            world.room_update(room)
        elif pid == 0x4385:
            room.clock = data[0]
            self.send(0x4386)
            world.room_update(room)
        elif pid == 0x4383:
            result = b"".join(i32(p.profile.id) + b"\0" * 18
                              for p in room.participants)
            self.send(0x4384, ZERO + pad(result, 88) + b"\0" * 20)
        else:
            log("Unimplemented lobby packet %04x; upstream-style empty ACK" % pid)
            self.send((pid + 1) & 0xffff)


def stun_attribute(kind, body):
    return struct.pack("!HH", kind, len(body)) + body + b"\0" * (-len(body) % 4)


def stun_address(kind, ip, port):
    return stun_attribute(kind, struct.pack("!BBH", 0, 1, port) + socket.inet_aton(ip))


def stun_response(data, peer, server_ip, port, other_port):
    """LAN Binding helper: RFC3489 framing, plus RFC5389 XOR-MAPPED-ADDRESS.

    Deliberately NOT a full two-address NAT-discovery server or a TURN relay.
    CHANGE-PORT is supported. CHANGE-IP cannot be fulfilled on one LAN IP.
    Never honor RESPONSE-ADDRESS: replies go only to the actual sender.
    """
    if len(data) < 20 or len(data) > 2048:
        return None
    typ, size = struct.unpack_from("!HH", data)
    if typ != 1 or len(data) != size + 20 or size % 4:
        return None
    flags, pos = 0, 20
    while pos < len(data):
        if pos + 4 > len(data):
            return None
        kind, length = struct.unpack_from("!HH", data, pos)
        end = pos + 4 + length
        if end > len(data):
            return None
        if kind == 3:
            if length != 4:
                return None
            flags = struct.unpack_from("!I", data, pos + 4)[0]
        pos = end + (-length % 4)
    source_port = other_port if flags & 2 else port
    alternative = port if flags & 2 else other_port
    attrs = (stun_address(1, peer[0], peer[1]) +
             stun_address(4, server_ip, source_port) +
             stun_address(5, server_ip, alternative))
    if data[4:8] == b"\x21\x12\xa4\x42":
        masked_ip = bytes(a ^ b for a, b in zip(socket.inet_aton(peer[0]), data[4:8]))
        attrs += stun_attribute(0x20, struct.pack("!BBH", 0, 1, peer[1] ^ 0x2112) + masked_ip)
    response = struct.pack("!HH", 0x0101, len(attrs)) + data[4:20] + attrs
    return source_port, response, bool(flags & 4)


class StunServer(asyncio.DatagramProtocol):
    def __init__(self, world, port):
        self.world, self.port = world, port
        self.transport = None
        self.change_ip_warning = False
        self.window, self.requests = time.monotonic(), 0

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, peer):
        if not is_lan(peer[0]):
            return
        if time.monotonic() - self.window >= 1:
            self.window, self.requests = time.monotonic(), 0
        self.requests += 1
        if self.requests > 100:
            return
        other_port = STUN_PORTS[1] if self.port == STUN_PORTS[0] else STUN_PORTS[0]
        result = stun_response(data, peer, self.world.ip, self.port, other_port)
        if result is None:
            return
        source_port, response, change_ip = result
        if change_ip and not self.change_ip_warning:
            self.change_ip_warning = True
            log("STUN: client requested CHANGE-IP. This is a one-IP LAN helper,")
            log("      not full NAT discovery; only CHANGE-PORT can be honored.")
        transport = next((t for t in self.world.udp_transports
                          if t.get_extra_info("sockname")[1] == source_port), self.transport)
        transport.sendto(response, peer)
        if self.world.debug:
            log("STUN %s:%d <- %s:%d" % (self.world.ip, source_port, peer[0], peer[1]))

# Windows setup is intentionally separate from the packet protocol.
HOSTS_BEGIN, HOSTS_END = "# PES6-LAN BEGIN", "# PES6-LAN END"
FIREWALL_RULES = ("PES6-LAN TCP server", "PES6-LAN UDP STUN", "PES6-LAN UDP game")


def clean_hosts(text):
    """Remove only our game hostnames, preserving unrelated aliases/comments."""
    domains, lines = set(GATEWAY_NAMES + STUN_NAMES), []
    for line in text.splitlines():
        if line.strip() in (HOSTS_BEGIN, HOSTS_END):
            continue
        body, sep, comment = line.partition("#")
        fields = body.split()
        if len(fields) >= 2 and any(t.lower() in domains for t in fields[1:]):
            keep = [t for t in fields[1:] if t.lower() not in domains]
            if keep:
                lines.append(fields[0] + " " + " ".join(keep) +
                             (" #" + comment if sep else ""))
            elif sep:
                lines.append("#" + comment)
        else:
            lines.append(line)
    return "\r\n".join(lines).rstrip("\r\n") + "\r\n"


def previous_mappings(text):
    domains, lines = set(GATEWAY_NAMES + STUN_NAMES), []
    for line in text.splitlines():
        fields = line.split("#", 1)[0].split()
        if len(fields) < 2:
            continue
        names = [t for t in fields[1:] if t.lower() in domains]
        if names:
            lines.append(fields[0] + " " + " ".join(names))
    return "\r\n".join(lines) + ("\r\n" if lines else "")


def netsh(*args, check=True):
    result = subprocess.run(["netsh"] + list(args), capture_output=True,
                            timeout=30, creationflags=0x08000000)
    if check and result.returncode:
        message = (result.stdout + result.stderr).decode("utf-8", "replace")
        raise OSError("netsh failed (%d): %s" % (result.returncode, message.strip()))
    return result.returncode


def host_setup(ip, udp_port, undo=False):
    path = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/drivers/etc/hosts"
    backup = path.with_name("hosts.pes6_lan.bak")
    text = path.read_bytes().decode("latin1") if path.exists() else ""
    if undo:
        if backup.exists():
            original = backup.read_bytes().decode("latin1")
            path.write_bytes((clean_hosts(text) + previous_mappings(original)).encode("latin1"))
            backup.unlink()
            log("Game host mappings restored; unrelated current entries retained.")
        else:
            log("No hosts backup found; leaving hosts unchanged.")
        for name in FIREWALL_RULES:
            netsh("advfirewall", "firewall", "delete", "rule", "name=" + name, check=False)
    else:
        if not backup.exists():
            with backup.open("xb") as out:
                out.write(text.encode("latin1"))
        patch = clean_hosts(text) + HOSTS_BEGIN + "\r\n"
        patch += "".join(ip + " " + name + "\r\n" for name in GATEWAY_NAMES + STUN_NAMES)
        path.write_bytes((patch + HOSTS_END + "\r\n").encode("latin1"))
        specs = (("TCP", "10881,20200-20202"), ("UDP", "3478-3479"), ("UDP", str(udp_port)))
        for name, (protocol, ports) in zip(FIREWALL_RULES, specs):
            netsh("advfirewall", "firewall", "delete", "rule", "name=" + name, check=False)
            netsh("advfirewall", "firewall", "add", "rule", "name=" + name,
                  "dir=in", "action=allow", "enable=yes", "profile=any",
                  "protocol=" + protocol, "localport=" + ports,
                  "remoteip=LocalSubnet")
        log("Windows host configured. Backup: %s" % backup)
    subprocess.run(["ipconfig", "/flushdns"], capture_output=True, timeout=15,
                   creationflags=0x08000000)


# A CMD/JScript hybrid. Both cmd.exe and cscript.exe are built into Windows XP.
# No PowerShell, downloaded executable, Python, .NET, or third-party runtime.
# JScript here uses only the ES3 features available in XP's Windows Script Host.
XP_SCRIPT = r'''@if (@X)==(@Y) @end /*
@echo off
setlocal DisableDelayedExpansion
cscript.exe //nologo //E:JScript "%~f0" "%~1"
set "PES6_RC=%ERRORLEVEL%"
echo.
pause
exit /b %PES6_RC%
*/
var IP = "__SERVER_IP__", PORT = __UDP_PORT__;
var NAMES = __DOMAINS__;
var BEGIN = "# PES6-LAN BEGIN", END = "# PES6-LAN END";
var fso = new ActiveXObject("Scripting.FileSystemObject");
var shell = new ActiveXObject("WScript.Shell");
var undo = WScript.Arguments.length > 0 && WScript.Arguments(0) == "--undo";
var root = shell.ExpandEnvironmentStrings("%SystemRoot%");
var hosts = root + "\\System32\\drivers\\etc\\hosts";
var backup = hosts + ".pes6_lan.bak";
function named(s) {
    for (var i = 0; i < NAMES.length; i++) if (s.toLowerCase() == NAMES[i]) return true;
    return false;
}
function trim(s) { return s.replace(/^\s+|\s+$/g, ""); }
function read(p) {
    if (!fso.FileExists(p)) return "";
    var h = fso.OpenTextFile(p, 1, false, 0), s = h.ReadAll(); h.Close(); return s;
}
function write(p, s) {
    var h = fso.CreateTextFile(p, true, false); h.Write(s); h.Close();
}
function clean(s) {
    var ls = s.split(/\r?\n/), result = [];
    for (var i = 0; i < ls.length; i++) {
        var line = ls[i];
        if (trim(line) == BEGIN || trim(line) == END) continue;
        var hash = line.indexOf("#"), body = hash < 0 ? line : line.substring(0, hash);
        var comment = hash < 0 ? "" : line.substring(hash);
        var parts = trim(body).split(/\s+/), keep = [], hit = false;
        for (var j = 1; j < parts.length; j++) {
            if (named(parts[j])) hit = true; else keep.push(parts[j]);
        }
        if (hit) {
            if (keep.length) result.push(parts[0] + " " + keep.join(" ") + (comment ? " " + comment : ""));
            else if (comment) result.push(comment);
        } else result.push(line);
    }
    return result.join("\r\n").replace(/[\r\n]+$/, "") + "\r\n";
}
function originals(s) {
    var ls = s.split(/\r?\n/), result = [];
    for (var i = 0; i < ls.length; i++) {
        var parts = trim(ls[i].split("#")[0]).split(/\s+/), keep = [];
        for (var j = 1; j < parts.length; j++) if (named(parts[j])) keep.push(parts[j]);
        if (keep.length) result.push(parts[0] + " " + keep.join(" "));
    }
    return result.length ? result.join("\r\n") + "\r\n" : "";
}
function run(s) { return shell.Run(s, 0, true); }
function firewall() {
    var profiles = [["STANDARD", "StandardProfile"], ["DOMAIN", "DomainProfile"]];
    var title = "PES6 LAN UDP " + PORT;
    var base = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\";
    for (var i = 0; i < profiles.length; i++) {
        var key = base + profiles[i][1] + "\\GloballyOpenPorts\\List\\" + PORT + ":UDP";
        var value = null;
        try { value = String(shell.RegRead(key)); } catch (e) {}
        var ours = value !== null && value.substring(value.length - title.length) == title;
        if (undo) {
            if (ours) run("netsh firewall delete portopening protocol=UDP port=" + PORT + " profile=" + profiles[i][0]);
        } else if (value === null || ours) {
            var rc = run('netsh firewall add portopening protocol=UDP port=' + PORT +
                ' name="' + title + '" mode=ENABLE scope=SUBNET profile=' + profiles[i][0]);
            if (rc) WScript.Echo("WARNING: firewall rule failed. XP SP2/SP3 is required for this command.");
        } else {
            WScript.Echo("Existing UDP " + PORT + " firewall entry kept (" + profiles[i][0] + ").");
        }
    }
}
try {
    WScript.Echo("PES6 LAN - Windows XP setup. Run with an Administrator account.");
    var current = read(hosts);
    if (undo) {
        if (fso.FileExists(backup)) {
            write(hosts, clean(current) + originals(read(backup)));
            fso.DeleteFile(backup, true);
            WScript.Echo("Old game mappings restored. Other current hosts entries retained.");
        } else WScript.Echo("No backup found. Hosts left unchanged.");
    } else {
        if (!fso.FileExists(backup)) write(backup, current);
        var updated = clean(current) + BEGIN + "\r\n";
        for (var i = 0; i < NAMES.length; i++) updated += IP + " " + NAMES[i] + "\r\n";
        write(hosts, updated + END + "\r\n");
        WScript.Echo("Game gateway and STUN now point to " + IP);
        WScript.Echo("Hosts backup: " + backup);
    }
    firewall();
    run("ipconfig /flushdns");
    if (!undo) {
        WScript.Echo("DONE. Restart PES6 if it was open. Game UDP port: " + PORT + "; UPnP: OFF.");
        WScript.Echo("Network -> any non-empty password -> Player profile -> PES6 LAN -> LAN.");
        WScript.Echo("No Python or other software is needed on this PC.");
        WScript.Echo("To undo later: PES6_XP_CONNECT.cmd --undo");
    }
} catch (e) {
    WScript.Echo("SETUP FAILED: " + e.message);
    WScript.Echo("Use an Administrator account. Do not disable the firewall or antivirus.");
    WScript.Echo("If hosts changed before this error, undo with: PES6_XP_CONNECT.cmd --undo");
    WScript.Quit(1);
}
'''


def make_xp_files(directory, ip, udp_port):
    # Values substituted here are validated, not arbitrary shell commands.
    ip = str(ipaddress.IPv4Address(ip))
    script = XP_SCRIPT.replace("__SERVER_IP__", ip).replace("__UDP_PORT__", str(udp_port))
    names = "[" + ",".join('"%s"' % n for n in GATEWAY_NAMES + STUN_NAMES) + "]"
    script = script.replace("__DOMAINS__", names)
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "PES6_XP_CONNECT.cmd"
    path.write_bytes(script.replace("\r\n", "\n").replace("\n", "\r\n").encode("ascii"))
    undo = '@echo off\r\ncall "%~dp0PES6_XP_CONNECT.cmd" --undo\r\n'
    (directory / "PES6_XP_UNDO.cmd").write_bytes(undo.encode("ascii"))
    return path


def local_addresses():
    result = {}
    if os.name == "nt":
        try:
            command = ("[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
                       "Get-NetIPAddress -AddressFamily IPv4 | "
                       "Where-Object {$_.AddressState -eq 'Preferred'} | "
                       "ForEach-Object {$_.IPAddress + '|' + $_.InterfaceAlias}")
            out = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
                                 capture_output=True, timeout=20, creationflags=0x08000000)
            for line in out.stdout.decode("utf-8-sig", "replace").splitlines():
                ip, sep, name = line.strip().partition("|")
                if sep and is_lan(ip) and not ip.startswith("127."):
                    result[ip] = name
        except (OSError, subprocess.TimeoutExpired):
            pass
    if not result:
        try:
            for item in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
                ip = item[4][0]
                if is_lan(ip) and not ip.startswith("127."):
                    result[ip] = "local IPv4"
        except OSError:
            pass
    return result


def choose_ip(explicit):
    if explicit:
        ip = explicit
    else:
        addresses = local_addresses()
        if len(addresses) == 1:
            ip = next(iter(addresses))
        else:
            print("Choose the adapter connected to the SAME LAN as the XP PC (not a VPN):")
            entries = list(addresses)
            for n, address in enumerate(entries, 1):
                print("  %d. %-15s %s" % (n, address, addresses[address]))
            answer = input("Adapter number, or this PC's LAN IPv4: ").strip()
            if answer.isdigit() and 1 <= int(answer) <= len(entries):
                ip = entries[int(answer) - 1]
            else:
                ip = answer
    try:
        ip = str(ipaddress.IPv4Address(ip))
    except ipaddress.AddressValueError:
        raise ValueError("Enter an IPv4 address, for example 192.168.1.10") from None
    if not is_lan(ip) or ip.startswith("127."):
        raise ValueError("Use this PC's LAN IPv4, not a public IP or 127.0.0.1")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind((ip, 0))  # fails immediately if this is not an assigned address
    return ip


def is_admin():
    return os.name == "nt" and bool(ctypes.windll.shell32.IsUserAnAdmin())


def elevate(extra_args):
    argv = [str(Path(__file__).resolve())] + sys.argv[1:] + list(extra_args)
    executable = sys.executable
    if executable.lower().endswith("pythonw.exe"):
        executable = str(Path(executable).with_name("python.exe"))
    result = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", executable, subprocess.list2cmdline(argv),
        str(Path(__file__).resolve().parent), 1)
    if result <= 32:
        raise OSError("Administrator permission was not granted. Nothing started.")


async def serve(args):
    world = World(args.ip, args.udp_port, args.debug)
    try:
        await world.open()
        if args.setup_yes and os.name == "nt":
            host_setup(args.ip, args.udp_port)
        folder = Path(args.output_dir) if args.output_dir else Path(__file__).resolve().parent
        helper = make_xp_files(folder, args.ip, args.udp_port)
        print("\n" + "=" * 66)
        print("READY: %s at %s" % (SERVER_NAME, args.ip))
        print("TCP: 10881, 20200, 20201, 20202 | STUN UDP: 3478, 3479")
        print("Game UDP: %d on BOTH PCs | UPnP: OFF" % args.udp_port)
        print("Stadium / match chat: %s | Lobby / room chat: ON" %
              ("OFF (keyboard mode)" if DISABLE_STADIUM_CHAT else "ON"))
        print("Copy to XP and run ONCE with an Administrator account:")
        print("  " + str(helper))
        print("Optional XP undo file: PES6_XP_UNDO.cmd (keep beside CONNECT.cmd)")
        print("In the game: Network -> any password -> Player -> PES6 LAN -> LAN")
        print("Room: Create / Join -> Participate -> Start match")
        print("Keep this window OPEN while playing. Ctrl+C stops the server.")
        print("All profiles, settings and rooms disappear when the server stops.")
        print("LAN ONLY. Never forward these server ports from the Internet.")
        print("=" * 66 + "\n")
        await asyncio.Event().wait()
    finally:
        await world.close()


def self_test():
    # Lightweight built-in checks, entirely offline; no files or system changes.
    assert parse_packet(make_packet(0x2005, b"", 13)) == (0x2005, b"", 13)
    for n in (1, 3, 4, 255, 1024, 65535):
        payload = bytes(i & 255 for i in range(n))
        assert parse_packet(make_packet(0x4350, payload, 9)) == (0x4350, payload, 9)
    bad = bytearray(make_packet(0x4350, b"a")); bad[-1] ^= 1
    try:
        parse_packet(bytes(bad))
        raise AssertionError("bad MD5 accepted")
    except ValueError:
        pass
    world = World("192.168.1.10")
    c = Connection(world, None, "192.168.1.20", "main")
    c.profile = world.new_profile(b"Tester")
    r = Room(1, b"Room", players=[c], participants=[c], owner=c)
    c.room = r
    assert len(r.info()) == 131
    assert r.info()[128] == (0 if DISABLE_STADIUM_CHAT else 2)
    assert len(r.participation()) == 24
    assert len(c.player_info()) == 127
    assert len(c.profile_info(c.profile)) == 418
    assert len(c.stun_info(c)) == 75
    assert len(c.stun_info(c, 36)) == 79
    request = struct.pack("!HH", 1, 0) + bytes(range(16))
    port, reply, change = stun_response(request, ("192.168.1.20", 5739), world.ip, 3478, 3479)
    assert port == 3478 and not change and reply[4:20] == request[4:20]
    assert reply[:4] == struct.pack("!HH", 0x101, 36)
    sample = "127.0.0.1 localhost\n1.2.3.4 unrelated pes6gate-ec.winning-eleven.net # keep\n"
    assert "1.2.3.4 unrelated # keep" in clean_hosts(sample)
    assert "localhost" in clean_hosts(sample)
    assert previous_mappings(sample) == "1.2.3.4 pes6gate-ec.winning-eleven.net\r\n"
    print("PASS: framing, checksums, record sizes, chat flag, STUN, hosts filtering.")
    print("This does not replace a real PES6 match test on Windows 11 / XP.")


def main():
    parser = argparse.ArgumentParser(description="PES6 PC LAN server: Python on host only, no dependencies.")
    parser.add_argument("--ip", help="Windows 11 LAN IPv4; normally detected automatically")
    parser.add_argument("--udp-port", type=int, default=GAME_UDP_PORT,
                        help="game UDP port to allow in firewall (default: 5739)")
    parser.add_argument("--no-setup", action="store_true", help="do not change host hosts/firewall")
    parser.add_argument("--setup-yes", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--undo", action="store_true", help="undo this Windows host's setup, then exit")
    parser.add_argument("--debug", action="store_true", help="log packet IDs/lengths, not authentication data")
    parser.add_argument("--output-dir", help="folder for generated XP CMD files (default: beside this script)")
    parser.add_argument("--self-test", action="store_true", help="offline checks; no system changes")
    args = parser.parse_args()
    if not 1024 <= args.udp_port <= 65535 or args.udp_port in STUN_PORTS:
        parser.error("game UDP port must be 1024..65535, excluding 3478 and 3479")
    if args.self_test:
        self_test()
        return 0
    if args.undo:
        if os.name != "nt":
            parser.error("--undo is for Windows; no automatic OS changes are made elsewhere")
        if not is_admin():
            elevate(())
            return 0
        host_setup(None, args.udp_port, undo=True)
        print("Host setup undone. Your Windows firewall has NOT been disabled.")
        return 0
    args.ip = choose_ip(args.ip)
    print("PES6 LAN host IPv4: %s | game UDP: %d" % (args.ip, args.udp_port))
    if os.name == "nt" and not args.no_setup:
        if not args.setup_yes:
            print("Setup will back up/edit game entries in hosts and add LAN-only firewall rules.")
            print("No game files are patched; no firewall is disabled.")
            args.setup_yes = input("Set up this HOST PC? [Y/n] ").strip().lower() not in ("n", "no")
        if args.setup_yes and not is_admin():
            elevate(("--ip", args.ip, "--setup-yes"))
            return 0
    elif os.name != "nt":
        args.setup_yes = False
        print("Non-Windows host: configure hosts/firewall manually. XP helper will still be created.")
    if args.no_setup:
        args.setup_yes = False
        print("Automatic host setup skipped. This PC's game still needs gateway/STUN redirection.")
    try:
        asyncio.run(serve(args))
    except KeyboardInterrupt:
        print("\nServer stopped. Temporary game data discarded.")
    return 0


# Original Fiveserver license, retained for this derived implementation:
# Copyright (c) 2011-2021 juce, reddwarf
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, EOFError, subprocess.TimeoutExpired) as exc:
        print("\nERROR: %s" % exc, file=sys.stderr)
        print("Check the LAN IPv4, administrator rights, and whether another server uses the ports.",
              file=sys.stderr)
        print("To reverse Windows host setup later: py pes6_lan.py --undo", file=sys.stderr)
        if os.name == "nt" and sys.stdin and sys.stdin.isatty():
            try:
                input("Press Enter to close...")
            except (EOFError, KeyboardInterrupt):
                pass
        sys.exit(1)
