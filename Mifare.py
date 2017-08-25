# -*- coding: UTF-8 -*-
from random import *
from FMReader import *
from struct import *
from binascii import *

class MifareSector:
	def __init__(self,access0=0x00,access1=0x00,access2=0x00,access3=0x01):
		self.access_b0=access0
		self.access_b1=access1
		self.access_b2=access2
		self.access_b3=access3
		self.access_b0	=0
		self.access_b1	=0
		self.access_b2	=0
		self.access_b3	=0
		self.sectordata	=[0,0,0,0]
		self.byte9_b3=0	
		self.value_b0=0
		self.value_b1=0
		self.value_b2=0
		self.value=[]
		self.addr_b0=0
		self.addr_b1=0
		self.addr_b2=0
		self.addr=[]
		self.Gen_sector()

	def Gen_random(self):
		value=randint((-2**9),(2**9))
		_value=value^0x0000FFFF
		value&=0x000000FF
		_value&=0x000000FF
		return [value,_value]

	def Gen_complement(self,dat):
		if dat>0x80000000:
			dat=dat^0x7FFFFFFF
			dat=dat+1
			dat=dat&0x7FFFFFFF
			dat=dat*(-1)
		else:
			dat=dat
		return dat

	def Gen_datablock(self):
		random_dat=self.Gen_random()
		addr 	=random_dat[0]
		_addr	=random_dat[1]
		random_dat=self.Gen_random()
		byte0 	=random_dat[0]
		_byte0 	=random_dat[1]
		random_dat=self.Gen_random()
		byte1 	=random_dat[0]
		_byte1 	=random_dat[1]		
		random_dat=self.Gen_random()
		byte2 	=random_dat[0]
		_byte2 	=random_dat[1]
		random_dat=self.Gen_random()
		byte3	=random_dat[0]
		_byte3 	=random_dat[1]
		block_list=[]
		block_list.append(_addr)
		block_list.append(addr)
		block_list.append(_addr)
		block_list.append(addr)
		block_list.append(byte0)
		block_list.append(byte1)
		block_list.append(byte2)
		block_list.append(byte3)
		block_list.append(_byte0)
		block_list.append(_byte1)
		block_list.append(_byte2)
		block_list.append(_byte3)
		block_list.append(byte0)
		block_list.append(byte1)
		block_list.append(byte2)
		block_list.append(byte3)
		return block_list

	def Gen_accessblock(self):
		self.keyA=[]
		self.keyB=[]
		for i in range(6):
			self.keyA.append(self.Gen_random()[0])
			self.keyB.append(self.Gen_random()[0])
		#Blockn_accessbits=0b'C1 C2 C3
		C1_b0=((self.access_b0>>2)&0x01)
		C2_b0=((self.access_b0>>1)&0x01)
		C3_b0=((self.access_b0>>0)&0x01)

		C1_b1=((self.access_b1>>2)&0x01)
		C2_b1=((self.access_b1>>1)&0x01)
		C3_b1=((self.access_b1>>0)&0x01)

		C1_b2=((self.access_b2>>2)&0x01)
		C2_b2=((self.access_b2>>1)&0x01)
		C3_b2=((self.access_b2>>0)&0x01)

		C1_b3=((self.access_b3>>2)&0x01)
		C2_b3=((self.access_b3>>1)&0x01)
		C3_b3=((self.access_b3>>0)&0x01)

		_C1_b0=((C1_b0^0x0F)&0x01)
		_C2_b0=((C2_b0^0x0F)&0x01)
		_C3_b0=((C3_b0^0x0F)&0x01)

		_C1_b1=((C1_b1^0x0F)&0x01)
		_C2_b1=((C2_b1^0x0F)&0x01)
		_C3_b1=((C3_b1^0x0F)&0x01)

		_C1_b2=((C1_b2^0x0F)&0x01)
		_C2_b2=((C2_b2^0x0F)&0x01)
		_C3_b2=((C3_b2^0x0F)&0x01)

		_C1_b3=((C1_b3^0x0F)&0x01)
		_C2_b3=((C2_b3^0x0F)&0x01)
		_C3_b3=((C3_b3^0x0F)&0x01)

		access_byte6=(_C2_b3<<7)|(_C2_b2<<6)|(_C2_b1<<5)|(_C2_b0<<4)|(_C1_b3<<3)|(_C1_b2<<2)|(_C1_b1<<1)|(_C1_b0<<0)
		access_byte7=(C1_b3<<7)	|(C1_b2<<6)	|(C1_b1<<5)	|(C1_b0<<4)	|(_C3_b3<<3)|(_C3_b2<<2)|(_C3_b1<<1)|(_C3_b0<<0)
		access_byte8=(C3_b3<<7)	|(C3_b2<<6)	|(C3_b1<<5)	|(C3_b0<<4)	|(C2_b3<<3)	|(C2_b2<<2)	|(C2_b1<<1)	|(C2_b0<<0)
		access_byte9=self.Gen_random()[0]
		self.byte9_b3=access_byte9
		access_bytes=[access_byte6,access_byte7,access_byte8,access_byte9]
		return self.keyA+access_bytes+self.keyB

	def Gen_sector(self,access0=0x00,access1=0x00,access2=0x00,access3=0x01):
		self.access_b0=access0
		self.access_b1=access1
		self.access_b2=access2
		self.access_b3=access3
		block0	=self.Gen_datablock()
		block1	=self.Gen_datablock()
		block2	=self.Gen_datablock()
		block3	=self.Gen_accessblock()
		self.value_b0	=(block0[7]<<24)|(block0[6]<<16)|(block0[5]<<8)|(block0[4]<<0)
		self.value_b1	=(block1[7]<<24)|(block1[6]<<16)|(block1[5]<<8)|(block1[4]<<0)
		self.value_b2	=(block2[7]<<24)|(block2[6]<<16)|(block2[5]<<8)|(block2[4]<<0)

		self.value_b0	=self.Gen_complement(self.value_b0)
		self.value_b1	=self.Gen_complement(self.value_b1)
		self.value_b2	=self.Gen_complement(self.value_b2)
		self.value=[self.value_b0,self.value_b1,self.value_b2]
		self.addr_b0	=block0[1]
		self.addr_b1	=block1[1]
		self.addr_b2	=block2[1]
		self.addr=[self.addr_b0,self.addr_b1,self.addr_b2]
		self.sectordata=[block0,block1,block2,block3]
		return self.sectordata

	def __del__(self):
		pass

class M1K:
	def __init__(self):
		self.sector=MifareSector()
		self.rdr=FMReader()
		self.M1K_Data=[]
		self.M1K_Value=[]
		self.M1K_Addr=[]
		self.M1K_Byte9=[]
		self.M1K_KeyA=[]
		self.M1K_KeyB=[]
		self.M1K_KeyAStr=[]
		self.M1K_KeyBStr=[]
		pass
	def IntToStr(self,dat):
		tmp=pack('B',dat)
		tmp=b2a_hex(tmp)
		return tmp

	def LongToStr(self,dat):
		tmp=pack('>I',dat)
		tmp=b2a_hex(tmp)
		return tmp	
			
	def StrtoInt(self,str):
		tmp=a2b_hex(str)
		tmp=unpack('B',tmp)[0]
		return tmp

	def Gen_M1K(self,access0=0x00,access1=0x00,access2=0x00,access3=0x01):
		self.M1K_Data=[]
		self.M1K_Value=[]
		self.M1K_Addr=[]
		self.M1K_Byte9=[]
		self.M1K_KeyA=[]
		self.M1K_KeyB=[]
		self.M1K_KeyAStr=[]
		self.M1K_KeyBStr=[]
		self.M1K_DataStr=[]
		for i in range(16):
			sectordat=self.sector.Gen_sector(access0,access1,access2,access3)
			self.M1K_Data.append(sectordat)
			self.M1K_Value.append(self.sector.value)
			self.M1K_Addr.append(self.sector.addr)
			self.M1K_Byte9.append(self.sector.byte9_b3)
			self.M1K_KeyA.append(self.sector.keyA)
			self.M1K_KeyB.append(self.sector.keyB)
		for i in range(16):
			for j in range(4):
				self.M1K_DataStr.append('')
				for m in range(16):
					tmpStr=self.IntToStr(self.M1K_Data[i][j][m])
					self.M1K_DataStr[i*4+j]+=tmpStr
		for i in range(16):
			tmpA=''
			tmpB=''
			for j in range(6):
				tmpA+=self.IntToStr(self.M1K_KeyA[i][j])
				tmpB+=self.IntToStr(self.M1K_KeyB[i][j])
			self.M1K_KeyAStr.append(tmpA)
			self.M1K_KeyBStr.append(tmpB)

	def FM349_DownloadInitData(self):
		self.rdr.InitCt(0)
		self.rdr.ColdReset('3V')
		self.rdr.DirectSendCt('0001950000')
		space=''
		for i in range(2*112):
			space+='0'
		for i in range(64):
			addr='0000B2'+self.LongToStr(0x6000+i*0x80)[4:8]
			dat=self.M1K_DataStr[i]
			self.rdr.DirectSendCt(addr)
			self.rdr.DirectSendCt(dat+space)
		pass
	

	def TailBlock_S0(self):
		#SUCCESS 0; ERROR 1;
		self.Gen_M1K(0x00,0x00,0x00,0x00)
		self.FM349_DownloadInitData()
		self.rdr.InitCl(0)	
		for i in range(16):
			blockn=self.IntToStr(i*4+0x03)
			retstr=self.rdr.MiAuthent('00',blockn,self.M1K_KeyAStr[i])
			if retstr!='9000':
				return 1
			retstr=self.rdr.MiRead(blockn) #Read TailBlock
			if retstr!=('000000000000'+self.M1K_DataStr[i*4+0x03][2*6:2*16]+'9000'):
				return 1
			retstr=self.rdr.MiWrite(blockn,'A0A1A2A3A4A5'+'FF0F00'+"B9"+"B0B1B2B3B4B5")
			if retstr!='9000':
				return 1
			retstr=self.rdr.MiRead(blockn)
			if retstr!=('000000000000'+self.M1K_DataStr[i*4+0x03][2*6:2*10]+'b0b1b2b3b4b5'+'9000'):
				return 1

			retstr=self.rdr.MiAuthent('01',blockn,"B0B1B2B3B4B5")
			if retstr!='9000':
				return 1

			retstr=self.rdr.MiWrite(blockn,'A0A1A2A3A4A5'+'FF0F00B9'+'B0B1B2B3B4B5')
			if retstr!='9000':
				return 1

			retstr=self.rdr.MiRead(blockn) #Read TailBlock
			if retstr!=('000000000000'+self.M1K_DataStr[i*4+0x03][2*6:2*10]+'b0b1b2b3b4b5'+'9000'):
				return 1
			return 0

	def TailBlock_S1(self):
		#SUCCESS 0; ERROR 1;
		self.Gen_M1K(0x00,0x00,0x00,0x01)
		self.FM349_DownloadInitData()
		self.rdr.InitCl(0)	
		for i in range(16):
			blockn=self.IntToStr(i*4+0x03)
			retstr=self.rdr.MiAuthent('00',blockn,self.M1K_KeyAStr[i])
			if retstr!='9000':
				return 1
			retstr=self.rdr.MiRead(blockn) #Read TailBlock
			if retstr!=('000000000000'+self.M1K_DataStr[i*4+0x03][2*6:2*16]+'9000'):
				return 1
			retstr=self.rdr.MiWrite(blockn,'A0A1A2A3A4A5'+'ff0780B9'+"B0B1B2B3B4B5")
			if retstr!='9000':
				return 1
			retstr=self.rdr.MiRead(blockn)
			if retstr!=('000000000000'+self.M1K_DataStr[i*4+0x03][2*6:2*9]+'b9'+'b0b1b2b3b4b5'+'9000'):
				return 1

			retstr=self.rdr.MiAuthent('01',blockn,"B0B1B2B3B4B5")
			if retstr!='9000':
				return 1

			retstr=self.rdr.MiWrite(blockn,'A0A1A2A3A4A5'+'ff0780B9'+'B0B1B2B3B4B5')
			if retstr!='9000':
				return 1

			retstr=self.rdr.MiRead(blockn) #Read TailBlock
			if retstr!=('000000000000'+self.M1K_DataStr[i*4+0x03][2*6:2*9]+'b9'+'b0b1b2b3b4b5'+'9000'):
				return 1
			return 0	

	def TailBlock_S2(self):
		#SUCCESS 0; ERROR 1;
		self.Gen_M1K(0x00,0x00,0x00,0x02) #7F0F08
		self.FM349_DownloadInitData()
		self.rdr.InitCl(0)	
		for i in range(16):
			blockn=self.IntToStr(i*4+0x03)
			retstr=self.rdr.MiAuthent('00',blockn,self.M1K_KeyAStr[i])
			if retstr!='9000':
				return 1
			retstr=self.rdr.MiRead(blockn) #Read TailBlock
			if retstr!=('000000000000'+self.M1K_DataStr[i*4+0x03][2*6:2*16]+'9000'):
				return 1
			retstr=self.rdr.MiWrite(blockn,'A0A1A2A3A4A5'+'7F0F08B9'+"B0B1B2B3B4B5")
			if retstr!='6700':
				return 1
			retstr=self.rdr.MiRead(blockn)
			if retstr!='6700':
				return 1

			self.rdr.InitCl(0)	
			retstr=self.rdr.MiAuthent('01',blockn,self.M1K_KeyBStr[i])

			if retstr!='9000':
				return 1

			retstr=self.rdr.MiRead(blockn) #Read TailBlock
			if retstr!=('000000000000'+self.M1K_DataStr[i*4+0x03][2*6:2*16]+'9000'):
				return 1

			retstr=self.rdr.MiWrite(blockn,'A0A1A2A3A4A5'+'7F0F08B9'+'B0B1B2B3B4B5')
			if retstr!='6700':
				return 1

			retstr=self.rdr.MiRead(blockn) #Read TailBlock
			if retstr!='6700':
				return 1
			return 0	

	def TailBlock_S3(self):
		#SUCCESS 0; ERROR 1;
		self.Gen_M1K(0x00,0x00,0x00,0x03) #7F0788
		self.FM349_DownloadInitData()
		self.rdr.InitCl(0)	
		for i in range(16):
			blockn=self.IntToStr(i*4+0x03)
			retstr=self.rdr.MiAuthent('00',blockn,self.M1K_KeyAStr[i])
			if retstr!='9000':
				return 1
			retstr=self.rdr.MiRead(blockn) #Read TailBlock
			if retstr!=('000000000000'+''+self.M1K_DataStr[i*4+0x03][2*6:2*10]+'000000000000'+'9000'):
				return 1
			retstr=self.rdr.MiWrite(blockn,'A0A1A2A3A4A5'+'ff0780B9'+"B0B1B2B3B4B5")
			if retstr!='6700':
				return 1

			self.rdr.InitCl(0)				
			retstr=self.rdr.MiAuthent('01',blockn,self.M1K_KeyBStr[i])
			if retstr!='9000':
				return 1

			retstr=self.rdr.MiRead(blockn) #Read TailBlock
			if retstr!=('000000000000'+self.M1K_DataStr[i*4+0x03][2*6:2*10]+'000000000000'+'9000'):
				return 1

			retstr=self.rdr.MiWrite(blockn,'A0A1A2A3A4A5'+'7F0788B9'+'B0B1B2B3B4B5')
			if retstr!='9000':
				return 1

			retstr=self.rdr.MiAuthent('01',blockn,'B0B1B2B3B4B5')
			if retstr!='9000':
				return 1				

			retstr=self.rdr.MiRead(blockn) #Read TailBlock
			if retstr!=('000000000000'+self.M1K_DataStr[i*4+0x03][2*6:2*9]+'b9'+'000000000000'+'9000'):
				return 1
			return 0	

	def TailBlock_S4(self):
		#SUCCESS 0; ERROR 1;
		self.Gen_M1K(0x00,0x00,0x00,0x04) #F78F00
		self.FM349_DownloadInitData()
		self.rdr.InitCl(0)	
		for i in range(16):
			blockn=self.IntToStr(i*4+0x03)
			retstr=self.rdr.MiAuthent('00',blockn,self.M1K_KeyAStr[i])
			if retstr!='9000':
				return 1
			retstr=self.rdr.MiRead(blockn) #Read TailBlock
			if retstr!=('000000000000'+self.M1K_DataStr[i*4+0x03][2*6:2*10]+'000000000000'+'9000'):
				return 1
			retstr=self.rdr.MiWrite(blockn,'A0A1A2A3A4A5'+'FF0F00'+"B9"+"B0B1B2B3B4B5")
			if retstr!='6700':
				return 1

			self.rdr.InitCl(0)

			retstr=self.rdr.MiAuthent('01',blockn,self.M1K_KeyBStr[i])
			if retstr!='9000':
				return 1
			retstr=self.rdr.MiRead(blockn) #Read TailBlock
			if retstr!=('000000000000'+self.M1K_DataStr[i*4+0x03][2*6:2*10]+'000000000000'+'9000'):
				return 1

			retstr=self.rdr.MiWrite(blockn,'A0A1A2A3A4A5'+'F78F00B9'+'B0B1B2B3B4B5')
			if retstr!='9000':
				return 1

			retstr=self.rdr.MiAuthent('00',blockn,'A0A1A2A3A4A5')
			if retstr!='9000':
				return 1

			retstr=self.rdr.MiAuthent('01',blockn,'B0B1B2B3B4B5')
			if retstr!='9000':
				return 1

			return 0

	def TailBlock_S5(self):
		#SUCCESS 0; ERROR 1;
		self.Gen_M1K(0x00,0x00,0x00,0x05) #F78780
		self.FM349_DownloadInitData()
		self.rdr.InitCl(0)	
		for i in range(16):
			blockn=self.IntToStr(i*4+0x03)
			retstr=self.rdr.MiAuthent('00',blockn,self.M1K_KeyAStr[i])
			if retstr!='9000':
				return 1
			retstr=self.rdr.MiRead(blockn) #Read TailBlock
			if retstr!=('000000000000'+self.M1K_DataStr[i*4+0x03][2*6:2*10]+'000000000000'+'9000'):
				return 1
			retstr=self.rdr.MiWrite(blockn,'A0A1A2A3A4A5'+'FF0F00'+"B9"+"B0B1B2B3B4B5")
			if retstr!='6700':
				return 1

			self.rdr.InitCl(0)

			retstr=self.rdr.MiAuthent('01',blockn,self.M1K_KeyBStr[i])
			if retstr!='9000':
				return 1
			retstr=self.rdr.MiRead(blockn) #Read TailBlock
			if retstr!=('000000000000'+self.M1K_DataStr[i*4+0x03][2*6:2*10]+'000000000000'+'9000'):
				return 1

			retstr=self.rdr.MiWrite(blockn,'A0A1A2A3A4A5'+'F78780B9'+'B0B1B2B3B4B5')
			if retstr!='9000':
				return 1

			retstr=self.rdr.MiRead(blockn) #Read TailBlock
			if retstr!=('000000000000'+self.M1K_DataStr[i*4+0x03][2*6:2*9]+'b9'+'000000000000'+'9000'):
				return 1	

			return 0

	def TailBlock_S6(self):
		#SUCCESS 0; ERROR 1;
		self.Gen_M1K(0x00,0x00,0x00,0x06) #778F08
		self.FM349_DownloadInitData()
		self.rdr.InitCl(0)	
		for i in range(16):
			blockn=self.IntToStr(i*4+0x03)
			retstr=self.rdr.MiAuthent('00',blockn,self.M1K_KeyAStr[i])
			if retstr!='9000':
				return 1
			retstr=self.rdr.MiRead(blockn) #Read TailBlock
			if retstr!=('000000000000'+self.M1K_DataStr[i*4+0x03][2*6:2*10]+'000000000000'+'9000'):
				return 1
			retstr=self.rdr.MiWrite(blockn,'A0A1A2A3A4A5'+'778F08'+"B9"+"B0B1B2B3B4B5")
			if retstr!='6700':
				return 1

			self.rdr.InitCl(0)

			retstr=self.rdr.MiAuthent('01',blockn,self.M1K_KeyBStr[i])
			if retstr!='9000':
				return 1
			retstr=self.rdr.MiRead(blockn) #Read TailBlock
			if retstr!=('000000000000'+self.M1K_DataStr[i*4+0x03][2*6:2*10]+'000000000000'+'9000'):
				return 1
			retstr=self.rdr.MiWrite(blockn,'A0A1A2A3A4A5'+'778F08'+"B9"+"B0B1B2B3B4B5")
			if retstr!='6700':
				return 1

			return 0

	def TailBlock_S7(self):
		#SUCCESS 0; ERROR 1;
		self.Gen_M1K(0x00,0x00,0x00,0x07) #778788
		self.FM349_DownloadInitData()
		self.rdr.InitCl(0)	
		for i in range(16):
			blockn=self.IntToStr(i*4+0x03)
			retstr=self.rdr.MiAuthent('00',blockn,self.M1K_KeyAStr[i])
			if retstr!='9000':
				return 1
			retstr=self.rdr.MiRead(blockn) #Read TailBlock
			if retstr!=('000000000000'+self.M1K_DataStr[i*4+0x03][2*6:2*10]+'000000000000'+'9000'):
				return 1
			retstr=self.rdr.MiWrite(blockn,'A0A1A2A3A4A5'+'778788'+"B9"+"B0B1B2B3B4B5")
			if retstr!='6700':
				return 1

			self.rdr.InitCl(0)

			retstr=self.rdr.MiAuthent('01',blockn,self.M1K_KeyBStr[i])
			if retstr!='9000':
				return 1
			retstr=self.rdr.MiRead(blockn) #Read TailBlock
			if retstr!=('000000000000'+self.M1K_DataStr[i*4+0x03][2*6:2*10]+'000000000000'+'9000'):
				return 1
			retstr=self.rdr.MiWrite(blockn,'A0A1A2A3A4A5'+'778788'+"B9"+"B0B1B2B3B4B5")
			if retstr!='6700':
				return 1

			return 0


	def DataBlock_S0(self):
		#SUCCESS 0; ERROR 1;
		self.Gen_M1K(0x00,0x00,0x00,0x01) 
		self.FM349_DownloadInitData()
		self.rdr.InitCl(0)	
		for i in range(16):
			for j in range(3):
				blockn=self.IntToStr(i*4+j)
				retstr=self.rdr.MiAuthent('00',blockn,self.M1K_KeyAStr[i])
				if retstr!='9000':
					return 1
				retstr=self.rdr.MiRead(blockn)
				if retstr!=(self.M1K_DataStr[i*4+j]+'9000'):
					return 1
				retstr=self.rdr.MiRestore(blockn)
				if retstr!='9000':
					return 1
				retstr=self.rdr.MiDecrement(blockn,'00000010')
				if retstr!='9000':
					return 1
				retstr=self.rdr.MiIncrement(blockn,'00000011')
				if retstr!='9000':
					return 1
				retstr=self.rdr.MiTransfer(blockn)
				if retstr!='9000':
					return 1
				retstr=self.rdr.MiWrite(blockn,self.M1K_DataStr[i*4+j])
				if retstr!='9000':
					return 1								

		return 0
				#retstr=self.rdr.MiDecrement(blockn,'')

				#retstr=self.rdr.MiWrite(blockn,'')







	def M1K_Ver(self):
		self.TailBlock_S0()
		self.TailBlock_S1()
		self.TailBlock_S2()
		self.TailBlock_S3()
		self.TailBlock_S4()
		self.TailBlock_S5()
		self.TailBlock_S6()
		self.TailBlock_S7()
		self.DataBlock_S0()
		self.DataBlock_S1()
		self.DataBlock_S2()
		self.DataBlock_S3()
		self.DataBlock_S4()
		self.DataBlock_S5()
		self.DataBlock_S6()
		self.DataBlock_S7()

	def __del__(self):
		pass
	


m=M1K()
m.rdr.InitCl(0)
m.rdr.MiAuthent('00','00','215ddbb38b34')
m.rdr.MiRead('00')
#m.Gen_M1K(0x00,0x00,0x00,0x01)

#print m.DataBlock_S0()
#print m.M1K_KeyAStr
#print m.M1K_KeyBStr
#print m.M1K_DataStr
#print m.M1K_Value


