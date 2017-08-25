from PythonDll import *

class instruct:
	InitTDA_1="FF1101050100"
	InitTDA_2="FF19010001"
	ColdReset_5V="FF1901010101"
	ColdReset_3V="FF1901010102"
	ColdReset_18V="FF1901010103"
	PPS_CT="FFFF000101"
	SEL_CT="FF0100000121"
	SEL_CL="FF0100000102"
	Reset17="FF1801000100"
	FieldON_1="FF1801000101"
	FieldON_2="FF1102260102"
	FieldON_3="FF1102210106"
	FieldON_4="FF11021E0101"
	PPS_CL="FFFF000001"  #pps1:0000+DSI+DRI
	REQA_1="FF11021E0101"
	REQA_2="FF18010102"
	AntiColl="FF18010206"
	Select="FF18010301"
	RATS="FF18010401"
	Authent='FF18010901'
	ReadBlock='FF18010501'
	WriteBlock="FF18010611"
	IncBlock="FF18011105"
	DecBlock="FF18011205"
	TransferBlock="FF18011401"
	RestoreBlock="FF18011301"
	Diselect="FF09010902CA01"

class FMReader:
	card=PyCard()
	ins=instruct()
	def GetReader(self):
		self.card.PyGetReader()

	def ConnectReader(self,ReaderID):
		self.card.PyConnectReader(ReaderID)
		

	def InitTDA(self):
		self.card.PyTransmitReader(self.ins.SEL_CT)
		self.card.PyTransmitReader(self.ins.InitTDA_1)
		ret1=self.card.RespData
		self.card.PyTransmitReader(self.ins.InitTDA_2)
		ret2=self.card.RespData
		print "InitTDA-> "+self.card.RespData



	def ColdReset(self,Volt):
		if Volt=="5V":
			self.card.PyTransmitReader(self.ins.ColdReset_5V)
		else:
			if Volt=="1.8V":
				self.card.PyTransmitReader(self.ins.ColdReset_18V)
			else :
				self.card.PyTransmitReader(self.ins.ColdReset_3V)
		print 'ColdReset-> '+self.card.RespData


	def PpsCt(self,pps1):
		self.card.PyTransmitReader(self.ins.PPS_CT+pps1)
		print "PPS-> "+self.card.RespData


	def SendApduCt(self,apdu):
		self.card.PyTransmitReader(apdu)
		print apdu+"-> "+self.card.RespData

	def Reset17(self):
		self.card.PyTransmitReader(self.ins.SEL_CL)
		self.card.PyTransmitReader(self.ins.Reset17)
		print "Reset17-> "+self.card.RespData

	def FieldON(self):
		self.card.PyTransmitReader(self.ins.FieldON_1)
		ret1=self.card.RespData
		self.card.PyTransmitReader(self.ins.FieldON_2)
		ret2=self.card.RespData
		self.card.PyTransmitReader(self.ins.FieldON_3)
		ret3=self.card.RespData
		self.card.PyTransmitReader(self.ins.FieldON_4)
		ret4=self.card.RespData
		print "FieldON-> "+self.card.RespData



	def ReqA(self):
		self.card.PyTransmitReader(self.ins.REQA_1)
		ret1=self.card.RespData
		self.card.PyTransmitReader(self.ins.REQA_2)
		ret2=self.card.RespData
		print "ReqA-> "+self.card.RespData


	def AntiColl(self):
		self.card.PyTransmitReader(self.ins.AntiColl)
		print "AntiColl-> "+self.card.RespData

	def Select(self):
		self.card.PyTransmitReader(self.ins.Select)
		print "Select-> "+self.card.RespData

	def Active(self):
		self.ReqA()
		self.AntiColl()
		self.Select()

	def Rats(self):
		self.card.PyTransmitReader(self.ins.RATS)
		print "RATS-> "+self.card.RespData

	def SendApduCL(self,apdu):
		self.card.PyTransmitReader(apdu)
		print apdu+"-> "+self.card.RespData

	def PpsCl(self,pps1):
		self.card.PyTransmitReader(self.ins.PPS_CL+pps1)
		print "PPS-> "+self.card.RespData		

	def MiAuthent(self,keytype,block,key):
		self.card.PyTransmitReader(self.ins.Authent+keytype+block+key)
		print "MiAuthent-> "+self.card.RespData
		return self.card.RespData

	def MiRead(self,block):
		self.card.PyTransmitReader(self.ins.ReadBlock+block)
		print "MiRead-> "+self.card.RespData
		return self.card.RespData

	def MiWrite(self,block,dat):
		self.card.PyTransmitReader(self.ins.WriteBlock+block+dat)
		print "MiWrite-> "+self.card.RespData
		return self.card.RespData
		
	def MiIncrement(self,block,dat):
		self.card.PyTransmitReader(self.ins.IncBlock+block+dat)
		print "MiIncrement-> "+self.card.RespData	
		return self.card.RespData

	def MiDecrement(self,block,dat):
		self.card.PyTransmitReader(self.ins.DecBlock+block+dat)
		print "MiDecrement-> "+self.card.RespData	
		return self.card.RespData

	def MiTransfer(self,block):
		self.card.PyTransmitReader(self.ins.TransferBlock+block)
		print "MiTransfer-> "+self.card.RespData	
		return self.card.RespData

	def MiRestore(self,block):
		self.card.PyTransmitReader(self.ins.RestoreBlock+block)
		print "MiRestore-> "+self.card.RespData			
		return self.card.RespData

	def MiDiselect(self):
		self.card.PyTransmitReader(self.ins.Diselect)
		print "MiRestore-> "+self.card.RespData	

	def DirectSendCL(self,crc_sel,dat): 
		#crc_sel: no_crc(00),all_crc(01),rx_crc(02),tx_crc(03)
		#do not support timeout config
		self.card.PyTransmitReader(self.ins.SEL_CL)
		sendlen=len(dat)
		if (sendlen%2)==0:
			sendlenstr=b2a_hex(pack('B',sendlen/2));
			self.card.PyTransmitReader("FF09"+crc_sel+"09"+sendlenstr+dat)
			print "DirectSendCL-> "+self.card.RespData
		else :
			print "DirectSendCL-> Input Wrong Data!"
	def DirectSendCt(self,dat):
		#do not support timeout config		
		self.card.PyTransmitReader(self.ins.SEL_CT)
		sendlen=len(dat)
		if (sendlen%2)==0:
			sendlenstr=b2a_hex(pack('B',sendlen/2));
			self.card.PyTransmitReader("FF090009"+sendlenstr+dat)
			print "DirectSendCT-> "+self.card.RespData
		else :
			print "DirectSendCT-> Input Wrong Data!"		

	def InitCt(self,ReaderID):
		self.GetReader()
		self.ConnectReader(ReaderID)
		self.Reset17()
		self.InitTDA()
		#self.ColdReset("3V")

	def InitCl(self,ReaderID):
		self.GetReader()
		self.ConnectReader(ReaderID)
		self.InitTDA()
		self.Reset17()
		self.FieldON()
		self.Active()
		#self.Rats()

	def __del__(self):
		self.card.PyDisconnectReader()

