# -*- coding: UTF-8 -*-
from random import *
from ctypes import *

class MifareSector:

	access_b0	=0
	access_b1	=0
	access_b2	=0
	access_b3	=0
	sectordata	=[0,0,0,0]

	keyA=[0,0,0,0,0,0]
	keyB=[0,0,0,0,0,0]
	byte9_b3=0
	
	value_b0=0
	value_b1=0
	value_b2=0

	addr_b0=0
	addr_b1=0
	addr_b2=0

	def __init__(self,access0,access1,access2,access3):
		self.access_b0=access0
		self.access_b1=access1
		self.access_b2=access2
		self.access_b3=access3

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
		for i in range(6):
			self.keyA[i]=self.Gen_random()[0]
			self.keyB[i]=self.Gen_random()[0]
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

	def Gen_sector(self):
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

		self.addr_b0	=block0[1]
		self.addr_b1	=block1[1]
		self.addr_b2	=block2[1]
		self.sectordata=[block0,block1,block2,block3]
		return self.sectordata

	def __del__(self):
		pass



m1=MifareSector(1,2,3,4)


m1.Gen_sector()
print m1.keyA
print m1.keyB
print m1.value_b0
print m1.value_b1
print m1.value_b2
print m1.addr_b0
print m1.addr_b1
print m1.addr_b2






