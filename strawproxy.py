#!/usr/bin/python3

import splice
from utils.nolog import *

SERVERNAME = "Factorio @ SERV"
PORT = 34197
SERVERS = {
	'alpha.factorio.sdore.me': ('172.20.0.2', 34197),
	'beta.factorio.sdore.me':  ('172.20.0.3', 34197),
	'gamma.factorio.sdore.me': ('172.20.0.4', 34197),
	'delta.factorio.sdore.me': ('172.20.0.5', 34197),
}

@singleton
class State:
	DISCONNECTED = -1
	INIT = 0
	CONNECT = 1
	LOOP = 2

	@dispatch
	def __init__(self):
		pass

	@dispatch
	def __init__(self, name, x):
		self.name, self.x = name, x

	def __repr__(self):
		return f"State.{self.name}"

	def __getattr__(self, x):
		try: return self.__class__(x, self.__class__.__dict__[x])
		except KeyError as ex: raise AttributeError() from ex

	def __eq__(self, other):
		return (self.x == other.x)

class FactorioProxyServer(Slots):
	class Client(Slots):
		sock: ...
		addr: ...
		state: State.DISCONNECTED
		version: ...
		cid: ...
		sid: ...
		s: ...

		def __init__(self, sock, addr):
			self.sock, self.addr = sock, addr
			self.state = State.INIT

		def proc(self, data=None):
			if (data is None):
				try: data = self.sock.recv(2048)
				except BlockingIOError: return
				except OSError as ex: logexception(ex); self.state = State.DISCONNECTED; return
			#self.lastpacket = time.time() # XXX

			dlog(self.state)
			if (self.state == State.INIT):
				dlog(data)
				m = re.fullmatch(rb'[\x02\x22]\x00\x00(.....)(....)', data, re.S)
				assert (m is not None)
				self.version, self.cid, self.sid = m[1], m[2], os.urandom(4)
				self.sock.send(bytes((*bytes.fromhex('c3 2880 0001000000 00'), *self.version, *self.cid, *self.sid)))
				self.state = State.CONNECT
			elif (self.state == State.CONNECT):
				m = re.fullmatch(rb'[\x04\x24]\x01\x00(....)(....)....(.+)', data, re.S)
				assert (m is not None)
				cid, sid, d = m.groups()
				assert (cid == self.cid and sid == self.sid)
				username, d = d[1:1+d[0]], d[1+d[0]:]
				dlog('username:', username)
				if (d): password, d = d[1:1+d[0]], d[1+d[0]:]
				else: password = None
				mods = d[10:]
				dlog('password:', password)

				if (not password):
					self.sock.send(bytes((
						*bytes.fromhex('c505 80000101000000'),
						*self.cid,
						0x06,
						len(servername := SERVERNAME.encode()), *servername,
						*bytes.fromhex('000020 3c ffffffff 0000000000000000'),
						len(serverusername := b'<server>'), *serverusername,
						*bytes.fromhex('ff0000'),
						0x6b,
						#len(username), *username,
						#*bytes.fromhex('00509d0100d0b6820d0800'),
						*bytes.fromhex('7d000000000000ffff'),
						*mods,
						0xff, 0xff,
					)))
					self.state = State.DISCONNECTED
					dlog('np')
					return

				for k, v in SERVERS.items():
					if (password == md5(k)[-8:].encode()):
						dlog(v)
						self.s = (Builder(socket.socket, socket.AF_INET, socket.SOCK_DGRAM)
						          .connect(v)
						         ).build()
						self.s.send(bytes((
							*bytes.fromhex('020000'),
							*self.version,
							*self.cid,
						)))
						r = bytearray()
						while (len(r) < 22):
							r += self.s.recv(22)
						dlog(r)
						m = re.fullmatch(rb'[\xc3\xe3].......\x00(.....)(....)(....)', r, re.S)
						version, cid, sid = m.groups()
						assert (version == self.version)
						assert (cid == self.cid)
						self.s.send(data.replace(self.sid, sid, 1))

						self.state = State.LOOP
						break
				else: self.state = State.DISCONNECTED; return
			elif (self.state == State.LOOP):
				s, c = self.s, self.sock
				while (not s._closed or not c._closed):
					try: splice.splice(c.fileno(), s.fileno(), nbytes=4096, flags=(splice.SPLICE_F_MOVE | splice.SPLICE_F_NONBLOCK))
					except BlockingIOError: pass
					try: splice.splice(s.fileno(), c.fileno(), nbytes=4096, flags=(splice.SPLICE_F_MOVE | splice.SPLICE_F_NONBLOCK))
					except BlockingIOError: pass
					#else:
					#	if (re.fullmatch(rb'[\x0e\x2e]....\x01...\x00', d, re.S) is not None):
					#		self.state = State.DISCONNECTED
					#		break

	addr: ...
	sock: ...
	clients: Slist

	def __init__(self, host, port=PORT):
		self.addr = (host, port)
		self.sock = (Builder(socket.socket, socket.AF_INET, socket.SOCK_DGRAM)
		             .setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
		             .bind(self.addr)
		             .setblocking(False)
		            ).build()

	def __del__(self):
		try: self.stop()
		except AttributeError: pass

	def proc(self):
		try: data, addr = self.sock.recvfrom(2048)
		except OSError: pass
		else:
			c = self.Client((Builder(socket.socket, socket.AF_INET, socket.SOCK_DGRAM)
			                 .setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
			                 .bind(self.addr)
			                 .connect(addr)
			                 .setblocking(False)
			                ).build(), addr)
			log(f"Connected: {c.addr}")

			try: c.proc(data)
			except Exception as ex:
				c.state = State.DISCONNECTED
				logexception(ex)
			if (c.state == State.DISCONNECTED):
				log(f"Disconnected: {c.addr}")
			else: self.clients.append(c)

		for ii, c in enumerate(self.clients.discard()):
			try: c.proc()
			except Exception as ex:
				c.state = State.DISCONNECTED
				logexception(ex)
			if (c.state == State.DISCONNECTED):
				log(f"Disconnected: {c.addr}")
				self.clients.to_discard(ii)
		self.clients.discard()

def main():
	s = FactorioProxyServer('', PORT)
	while (True):
		try: s.proc()
		except Exception as ex: exception(ex)
		except KeyboardInterrupt as ex: exit(ex)

if (__name__ == '__main__'): exit(main())

# by Sdore, 2021-22
#   www.sdore.me
