import math
import timeit
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve,Point

from Crypto.Hash import SHA3_256
import requests
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import random
import re
import json
API_URL = 'Enter your API URL here'


stuID = "23813"

E = Curve.get_curve('secp256k1')
n = E.order
P = E.generator

curve = E

random.seed(107)
secretkey = random.randint(0, E.order-2)

# I hardcode the secret key here
secretkey = 49244014148938005952377150003658526738643370915148588522516277486091253674270

Qa = secretkey*P # my public key
#print("Q on curve?", E.is_on_curve(Qa))

# signature generation
random.seed(112)
k = random.randint(0, E.order-3)
ephemeral_sk = k
R = k*P
lower_r = (R.x) % n
msg = bytearray('23813'.encode())
hashdata = msg + lower_r.to_bytes((lower_r.bit_length()+7)//8, byteorder='big')

h_object = SHA3_256.new()
h_object.update(data=hashdata)

h = (int.from_bytes(h_object.digest(), byteorder='big'))% n
s = ((secretkey*int.from_bytes(h_object.digest(), byteorder='big'))+k) % n


#compute lkey here
#lkeyx = Qa.x
#lkeyy = Qa.y


# I hardoce lkey here but you can compute it above
lkeyx = 68110525590023252110691331053827389182171619475153758528176940072728454087100
lkeyy = 72450857802691432767830303644512687764858135324384751687549244427320503637268

# I hardoce the h, s here but you can compute it above
h = 24726638414312104064780700376437763300150884611078947863520261547184694254609
s = 12271127558495818433731373760804863696993481817607137293272292657829912113907





print("long term public x:")
print(lkeyx)
print("************")
print("long term public x:")
print(lkeyy)
print("************")
print("secret key:" , secretkey)
print("************")
print("h:", h)
print("************")
print("s: ", s)


#server's long term key
QSer_long = Point(0xc1bc6c9063b6985fe4b93be9b8f9d9149c353ae83c34a434ac91c85f61ddd1e9 , 0x931bd623cf52ee6009ed3f50f6b4f92c564431306d284be7e97af8e443e69a8c, curve)

# HERE GENERATE A EPHEMERAL KEY 
random.seed(78)
e_secret = random.randint(0, E.order-2) #Sa
Q_ephemeral = e_secret*P
ekeyx = Q_ephemeral.x
ekeyy = Q_ephemeral.y



try:
	#REGISTRATION
	mes = {'ID':stuID, 'h': h, 's': s, 'LKEY.X': lkeyx, 'LKEY.Y': lkeyy}
	response = requests.put('{}/{}'.format(API_URL, "RegStep1"), json = mes)		
	if((response.ok) == False): raise Exception(response.json())
	print(response.json())

	print("Enter verification code which is sent to you: ")	
	#code = int(input())
	code = 492557
	
	mes = {'ID':stuID, 'CODE': code}
	response = requests.put('{}/{}'.format(API_URL, "RegStep3"), json = mes)
	if((response.ok) == False): raise Exception(response.json())
	print(response.json())



	#STS PROTOCOL

	mes = {'ID': stuID, 'EKEY.X': ekeyx, 'EKEY.Y': ekeyy}
	response = requests.put('{}/{}'.format(API_URL, "STSStep1&2"), json = mes)
	if((response.ok) == False): raise Exception(responce.json())
	res=response.json()
	print("type res: ", type(res))
	key_pair = list(res.values())
	print("dict values: ", key_pair)
	skeyx = key_pair[0]
	skeyy = key_pair[1]
	Q_b = Point(skeyx, skeyy, curve)



	#calculate T,K,U
	T = e_secret * Q_b
	U = str(int(str(T.x) + str(T.y))) + "BeYourselfNoMatterWhatTheySay"
	hdata = bytearray(U.encode())

	K_session = SHA3_256.new()
	K_session.update(data=hdata)
	
	print("Session key: ", K_session.hexdigest())
	# session key: 60b72aa2b1c2d55a7539725dd36dffbf8a9a35735a6869e834ac8ebb3f784b66

	#Sign Message
	W_1 = str(ekeyx) + str(ekeyy) + str(Q_b.x) + str(Q_b.y)
	random.seed(64)
	k_2 = random.randint(0, E.order-3)
	R = ephemeral_sk*P
	lower_r = (R.x) % n
	w1_msg = bytearray(W_1.encode())
	hashdata = w1_msg + lower_r.to_bytes((lower_r.bit_length()+7)//8, byteorder='big')
	h_object = SHA3_256.new()
	h_object.update(data=hashdata)
	h = (int.from_bytes(h_object.digest(), byteorder='big'))% n
	sig_a = ((secretkey*int.from_bytes(h_object.digest(), byteorder='big'))+k) % n
	
	key = int.from_bytes(K_session.digest(), byteorder='big')
	
	# Encryption
	
	cipher = AES.new(key.to_bytes((key.bit_length()+7)//8, byteorder='big'), AES.MODE_CTR)
	ptext = "s" + str(sig_a) + "h" + str(h)
	ctext = cipher.encrypt(bytearray(ptext.encode()))
	print("ctext: ", ctext)
	print("nonce: ", cipher.nonce)
	temp_array = bytearray(cipher.nonce)
	temp1_array = temp_array + ctext
	
	
	print(temp1_array)
	Y_1 = int.from_bytes(temp1_array, byteorder='big')
	
	ctext = Y_1
	print("type ctext:", type(ctext))



	###Send encrypted-signed keys and retrive server's signed keys
	mes = {'ID': stuID, 'FINAL MESSAGE': ctext}
	response = requests.put('{}/{}'.format(API_URL, "STSStep4&5"), json = mes)
	if((response.ok) == False): raise Exception(response.json()) 
	ctext= response.json() 


	#Decrypt 
	ctext = ctext.to_bytes((ctext.bit_length()+7)//8, byteorder='big')
	
	s_cipher = AES.new(key.to_bytes((key.bit_length()+7)//8, byteorder='big'), AES.MODE_CTR, nonce=ctext[0:8])
	
	dtext = s_cipher.decrypt(ctext[8:])
	print("dtext: ", dtext.decode('UTF-8'))
	
	print("type dtext: ", type(dtext))
	dtext = dtext.decode('UTF-8')
	split_list = dtext.split("h")
	
	sigb_s = split_list[0].replace('s', '')
	
	sigb_h = split_list[1]
	
	print("sigb_h", sigb_h)
	print("sigb_s", sigb_s)




	#verify
	W_2 = str(Q_b.x) + str(Q_b.y) + str(ekeyx) + str(ekeyy)
	V = (int(sigb_s)*P) - (int(sigb_h)*QSer_long)
	lower_v = V.x % n
	servermsg = bytearray(W_2.encode())
	hp_data = servermsg + lower_v.to_bytes((lower_v.bit_length()+7)//8, byteorder='big')
	h_prime = SHA3_256.new()
	h_prime.update(data=hp_data)
	hashprime = (int.from_bytes(h_prime.digest(), byteorder='big'))% n
	if(sigb_h == str(hashprime)):
		print("Accept!")
		print(hashprime)

	else:
		print("Reject!")
		print(hashprime)

	#get a message from server for 
	mes = {'ID': stuID}
	response = requests.get('{}/{}'.format(API_URL, "STSStep6"), json=mes)
	ctext= response.json()         
	

	#Decrypt
	ctext = ctext.to_bytes((ctext.bit_length()+7)//8, byteorder='big')
	
	s_cipher = AES.new(key.to_bytes((key.bit_length()+7)//8, byteorder='big'), AES.MODE_CTR, nonce=ctext[0:8])
	
	dtext = s_cipher.decrypt(ctext[8:])
	print("new dtext: ", dtext.decode('ISO-8859-1'))
	print("last 8:", dtext[-8:].decode('ISO-8859-1'))
	rand_number = int(str(dtext[-6:].decode('ISO-8859-1')))
	extract_rand = re.findall(r'\b\d+\b', str(dtext))
	rand_number = int(extract_rand[0])
	print("rand: ", rand_number)
	print("rand + 1: ", rand_number+1)
	message_to_server = ''.join([i for i in str(dtext.decode('ISO-8859-1')) if not i.isdigit()])
	#message_to_server = str(dtext[:-6].decode('ISO-8859-1'))

	print("message_to_server", str(dtext[:-7].decode('ISO-8859-1')))
	# When you read this message I'll be far away. 282183



	#Add 1 to random to create the new message and encrypt it
	
	W_4 = message_to_server + str(rand_number+1)
	print("W4: ", W_4)
	cipher = AES.new(key.to_bytes((key.bit_length()+7)//8, byteorder='big'), AES.MODE_CTR)
	ctext = cipher.encrypt(bytearray(W_4.encode()))
	
	temp_array = bytearray(cipher.nonce)
	temp1_array = temp_array + ctext
	ct = int.from_bytes(temp1_array, byteorder='big')
	
	#send the message and get response of the server
	mes = {'ID': stuID, 'ctext': ct}
	response = requests.put('{}/{}'.format(API_URL, "STSStep7&8"), json = mes)
	ctext= response.json()         

	print("last ctext:", ctext)
	ctext = ctext.to_bytes((ctext.bit_length()+7)//8, byteorder='big')
	
	s_cipher = AES.new(key.to_bytes((key.bit_length()+7)//8, byteorder='big'), AES.MODE_CTR, nonce=ctext[0:8])
	
	dtext = s_cipher.decrypt(ctext[8:])
	print("last dtext: ", dtext.decode('ISO-8859-1'))



except Exception as e:
	print(e)
