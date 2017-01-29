import sys
import string
import socket

from cStringIO import StringIO
from SocketServer import TCPServer, StreamRequestHandler
from struct import *
import MySQLdb
import random

class myDB:
	db = ''
	nb_jobs = 0
	
	def __init__(self):
		self.db=MySQLdb.connect(user="root",db="btb")
		self.db.autocommit(True)
		c = self.db.cursor()
		c.execute("""SELECT count(*) FROM jobs WHERE status='active'""")
		self.nb_jobs = c.fetchone()[0]
		c.close()

	def find_client(self, id):
		c = self.db.cursor()
		c.execute("""SELECT username,sysname,jobid FROM clients WHERE clientid=%s""", id)
		out = c.fetchone()
		c.close()
		return out
	
	def new_client(self, id, username, capabilities):
		c = self.db.cursor()
		c.execute("""INSERT INTO clients (clientid, login, last_ping, capabilities, username, cracked) VALUES (%s, NOW(), NOW(), %s, %s, 0);""", (id, capabilities, self.db.escape_string(username)))
		c.close()
		
	def update_client(self, id):
		c = self.db.cursor()
		c.execute("""UPDATE clients SET last_ping=NOW() WHERE clientid=%s""", id)
		c.close()

	def client_info(self, id, sysname, release, machine):
		c = self.db.cursor()
		c.execute("""UPDATE clients SET sysname=%s, releases=%s, machine=%s WHERE clientid=%s""", (sysname, release, machine, id))
		c.close()

	def found_password(self, id, username, password, cleartext):
		c = self.db.cursor()
		print "password found %s/%s" % (username, cleartext)
		c.execute("""UPDATE passwords SET cleartext=%s WHERE username=%s AND hash=%s AND jobid IN (SELECT jobs.id FROM jobs JOIN clients ON clients.jobid=jobs.id WHERE clients.clientid=%s)""", (cleartext, username, password, id))
		c.close()

	def job_change_status(self, id, status):
		c = self.db.cursor()
		print "changing status for client %s : %s" % (id, status)
		if(status=='done'):
			c.execute("""UPDATE clients SET jobid=NULL, cracked=cracked+(SELECT MAX(end-start) FROM spaces WHERE clientid=%s AND status='doing') WHERE clientid=%s""", (id, id))
		c.execute("""UPDATE spaces SET status=%s WHERE status='doing' AND clientid=%s""", (status, id))
		c.close()
		
	def give_work(self, id):
		c = self.db.cursor()
		c.execute("""UPDATE jobs SET curprio=curprio+1""")
		
		#find job id
		c.execute("""SELECT id, cipher, interval_size, crack_method FROM jobs where status='active' ORDER BY (curprio*priority) DESC""")
		job = c.fetchone()
		if(job == None):
			return None #nojob
		jobid = job[0]
		cipher = job[1]
		interval_size = job[2]
		crack_method = job[3]
		if(interval_size == None):
			interval_size = 10000000
		if(crack_method == None):
			crack_method = 0

		#reduce prio
		c.execute("""UPDATE jobs SET curprio=curprio-%s WHERE id=%s""", (self.nb_jobs, jobid))

		#count nb pwd
		c.execute("""SELECT count(*) FROM passwords WHERE jobid=%s AND cleartext IS NULL""", (jobid))
		nb_passwords = c.fetchone()[0]

		#find space
		c.execute("""SELECT start,end,status, count(*) AS nb FROM spaces WHERE passwordid IN 
				(SELECT passwords.id FROM passwords WHERE jobid=%s AND cleartext IS NULL) 
			GROUP BY start,end,status ORDER BY start""", jobid)
		ok = 1
		#ligne = (10,20,'coin')
		prevend = 0
		while( ok ):
			ligne = c.fetchone()
			if(ligne == None):
				break
			ok = 2
			curstart = ligne[0]
			curend = ligne[1]
			curstatus = ligne[2]
			print "[%d:%d]=%s / %d" % (curstart, curend, curstatus, ligne[3])
			if ( prevend != curstart ):
				print "prevend != curstart !=?!?"
				curend = curstart
				curstart = prevend
				curstatus = 'todo'
			if ( (curstatus == 'aborted') or (ligne[3]!=nb_passwords) ):
				curstatus = 'aborted'
				break
			prevend = curend

		new = 0

		if(ok==1):
			curstart = 0
			curend = 0
			curstatus = ""

		if( curstatus != 'aborted' ):
			new = 1
			curstart = curend;
			curend += interval_size; #FIXME

		print "selecting job id=%d, allocating space [%d:%d], max pwd=%d" % (jobid, curstart, curend, nb_passwords)

		#find passwords
		c.execute("""SELECT passwords.id, username, hash FROM passwords 
				LEFT JOIN spaces ON spaces.passwordid=passwords.id AND spaces.start>=%s AND spaces.end<=%s AND spaces.status!='aborted' 
				WHERE cleartext IS NULL 
				AND passwords.salt IN (SELECT DISTINCT salt FROM passwords WHERE cleartext IS NULL AND jobid=%s) 
				AND spaces.id IS NULL""" , (curstart, curend, jobid))

		nb = 0
		ids = []

		while( ok ):
			k = c.fetchone()
			ids.insert(0,k)
			if(k == None):
				break
			nb+=1
			
		c.execute("""UPDATE clients SET jobid=%s WHERE clientid=%s""", (jobid, id))

		for elm in ids:
			if(elm == None):
				continue
			c.execute("""UPDATE spaces SET status='doing', clientid=%s WHERE start=%s AND end=%s and passwordid=%s""", (id, curstart, curend, elm[0]))
			if(self.db.affected_rows()!=1):
				c.execute("""INSERT INTO spaces (start, end, status, passwordid, clientid) VALUES (%s, %s, 'doing', %s, %s)""", (curstart, curend, elm[0], id))

		c.close()

		return [(jobid, cipher, crack_method, curstart, curend),ids]
			

database = myDB()

class netPacket:
	psize = 0
	type = 0
	cmd = 0
	data = ''
	seed = ''
	def __init__(self, s):
		try:
			got1 = s.recv(4)
			newseed = s.recv(8)
			got2 = s.recv(2)
		except:
			print "only got %d bytes" % (len(got))
			return 0
		header = unpack("!I", got1)
		self.psize = header[0] - 2
		header = unpack("!BB", got2)
		self.type = header[0] & 0xff
		self.cmd = header[1] & 0xff
		if(self.psize > 65535):
			self.psize = 0
			#todo raise error
		if(newseed != self.seed):
			self.seed = newseed
			self.init_cryptostate()
		self.s = s

	def adddata(self, data):
		self.data += data

	def flush(self):
		self.s.write(data)
		
	def init_cryptostate(self):
		print "cryptostate for seed %0.16x" % (unpack("!Q", self.seed) )
		
	def getdata(self):
		self.data = StringIO(self.s.recv(self.psize))
		
	def close(self):
		self.s.close()
		
	def __repr__(self):
		return 'netpacket psize=0x%x / type=%x / cmd=%x' % (self.psize, self.type, self.cmd)

	def __str__(self):
		return self.__repr__()

class sendPacket:
	psize = 0
	type = 0
	cmd = 0
	data = ''
	seed = ''

	def __init__(self, s, t, c):
		self.type = t
		self.cmd = c
		self.seed = self.genseed()
		self.psize = 2
		self.request = s

	def genseed(self):
		return "abcdefgh"

	def flush(self):
		tosend = pack("!BB", self.type, self.cmd) + self.data
		#crypt
		self.request.send(pack("!I", self.psize) + self.seed + tosend)
		print "sent packet type=%d cmd=%d size=%d" % (self.type, self.cmd, self.psize)
	
	def add_data(self, data):
		self.psize += len(data)
		self.data += data
	
	def add_netstring(self, nstr):
		self.add_data(pack("!I", len(nstr) ) + nstr)
	
	def add_uint32(self, i):
		self.add_data(pack("!I", i))

	def add_uint64(self, i):
		self.add_data(pack("!Q", i))
	
	def add_uint8(self, i):
		self.add_data(pack("!B", i))

class myHandler(StreamRequestHandler):
	functable = []
	
	def read_netstring(self):
		size = unpack("!I", self.packet.data.read(4))[0]
		return self.packet.data.read(size)
	
	def read_uint8(self):
		return unpack("!B", self.packet.data.read(1))[0]
	
	def read_uint32(self):
		return unpack("!I", self.packet.data.read(4))[0]

	def read_uint64(self):
		return unpack("!Q", self.packet.data.read(8))[0]

	def client_idle(self):
		id = self.read_uint32()
		capabilities = self.read_uint64()
		username = self.read_netstring()
		print "client_idle id=%x cap=%x username=%s" % (id, capabilities, username)
		client = database.find_client(id)
		if(client == None):
			id = random.randint(0, 2**32-1)
			print "new id : %d" % (id)
			idp = sendPacket(self.request, 0xf0, 0x01) #idle
			idp.add_uint32(id)
			idp.flush()
			database.new_client(id, username, capabilities)
		else:
			database.update_client(id)
			if(client[1] == None):
				idp = sendPacket(self.request, 0xf0, 0x02) #info
				idp.flush()
			else:
				if ( client[2] != None ):
					print "This one should already be working"
				else:
					work = database.give_work(id)
					#give work
					if(work == None):
						idp = sendPacket(self.request, 0xf0, 0x03) # nojob
						idp.flush()
					else:
						params = work[0]
						passwords = work[1]
						
						idp = sendPacket(self.request, 0xf0, 0x04) #work
						idp.add_uint32(params[0])
						idp.add_uint32(params[1])
						idp.add_uint32(params[2])
						idp.add_uint32(passwords.__len__()-1)
						idp.add_uint64(params[3])
						idp.add_uint64(params[4])

						for pwd in passwords:
							if(pwd == None):
								continue
							#print "adding " + pwd[1] + " " + pwd[2]
							idp.add_netstring(pwd[1])
							idp.add_netstring(pwd[2])
						idp.flush()

					
		
	def client_info(self):
		id = self.read_uint32()
		client = database.find_client(id)
		if(client == None):
			return
		database.update_client(id)
		sysname = self.read_netstring()
		release = self.read_netstring()
		machine = self.read_netstring()
		database.client_info(id, sysname, release, machine)
		
	def client_pwdfound(self):
		id = self.read_uint32()
		username = self.read_netstring()
		pwd = self.read_netstring()
		cleartext = self.read_netstring()
		database.found_password(id, username, pwd, cleartext)
		
	def client_jobfinish(self):
		id = self.read_uint32()
		database.job_change_status(id, "done")
		
	def client_jobabort(self):
		id = self.read_uint32()
		database.job_change_status(id, "aborted")
		
	def client_default(self):
		print "client_default - should do something ** REALLY **"
		
	def init_functable(self):
		for i in range(255):
			self.functable.append(self.client_default)
		self.functable[ 0xF0 | 0x1 ] = self.client_idle
		self.functable[ 0xF0 | 0x2 ] = self.client_info
		self.functable[ 0xF0 | 0x3 ] = self.client_pwdfound
		self.functable[ 0xF0 | 0x4 ] = self.client_jobfinish
		self.functable[ 0xF0 | 0x5 ] = self.client_jobabort
	
	def handle_client(self):
		print "handle client"

	def handle(self):
		self.init_functable()
		print 'got connection from %s:%d' % (self.client_address[0], self.client_address[1])
		self.packet = netPacket(self.request)
		print 'packet = %s' % (self.packet)
		if( self.packet.type == 0 ): #admin
			print "admin"
		else:
			self.packet.getdata()
			self.functable[self.packet.cmd]()

random.seed(None)
server = TCPServer( ('', 9034), myHandler)
server.serve_forever()
