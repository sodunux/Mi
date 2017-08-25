from ctypes import *
from struct import *
from binascii import *
PyDll=CDLL("PythonDll.dll")

class PyCard:
	ReaderNames=[]
	ReaderCnt=0
	RespData=''
	RespLen=0
	def PyGetReader(self):
		ReaderNames=[]
		Readerbuff=''
		for i in range(0x80):
			Readerbuff+='\x00'
		PyGetReader=PyDll.GetReaders
		PyGetReader.argtypes=[c_char_p]
		PyGetReader.restype=c_int
		ret=PyGetReader(Readerbuff)
		strend=Readerbuff.index('\x00\x00')
		self.ReaderCnt=Readerbuff.count('\x00',0,strend+1)
		substr_start=0
		substr_end=0
		for i in range(self.ReaderCnt):
			if substr_end==0:
				substr_start=substr_end
			else :
				substr_start=substr_end+1
			substr_end=Readerbuff.index('\x00',substr_start,strend+1)
			self.ReaderNames.append(Readerbuff[substr_start:substr_end])
		print self.ReaderNames
#		if ret==0:
#			print "Get Readers Succeed"
#		else :
#			print "Get Readers Failed"
		return ret

	def PyConnectReader(self,ReaderID):
		PyConnectReader=PyDll.ConnectReader
		PyConnectReader.argtypes=[c_char_p]
		PyConnectReader.restype=c_int
		ret=PyConnectReader(self.ReaderNames[ReaderID])
		if ret==0:
			print "Connect Reader Succeed"
		else : 
			print "Connect Reader Failed"
		return ret

	def PyTransmitReader(self,sendstr):
		request=''
		respbuff=''
		resplen='\x00'
		for i in range(0xFF):
			respbuff+='\x00'
		request=a2b_hex(sendstr)
		PyTransmitReader=PyDll.TransmitReader
		PyTransmitReader.argtypes=[c_char_p,c_int,c_char_p,c_char_p]
		PyTransmitReader.restype=c_int
		ret=PyTransmitReader(request,len(request),respbuff,resplen)
		
		self.RespLen=unpack('B',resplen)[0]
		#special for len=1
		if self.RespLen==0x01:
			self.RespLen=0x02
			subbuff=respbuff[0:self.RespLen]
			self.RespData=b2a_hex(subbuff)[0:2]
			self.RespLen=0x01
		else :
			subbuff=respbuff[0:self.RespLen]
			self.RespData=b2a_hex(subbuff)		
		
	def PyDisconnectReader(self):
		PyDisconnectReader=PyDll.DisconnectReader
		PyDisconnectReader.restype=c_int
		ret=PyDisconnectReader()

		if ret==0:
			print "Disconnect Reader Succeed!"
		else : 
			print "Disconnect Reader Failed!"
		return ret

	







