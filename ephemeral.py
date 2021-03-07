import math
import timeit
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256, HMAC, SHA256
import requests
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import random
import re
import json
API_URL = 'Enter your API URL'

stuID = 23813
E = Curve.get_curve('secp256k1')
n = E.order
P = E.generator

curve = E

secretkey = 49244014148938005952377150003658526738643370915148588522516277486091253674270
#create a long term key
lkeyx = 68110525590023252110691331053827389182171619475153758528176940072728454087100
lkeyy = 72450857802691432767830303644512687764858135324384751687549244427320503637268

# I hardoce the specific h, s here
h = 24726638414312104064780700376437763300150884611078947863520261547184694254609
s = 12271127558495818433731373760804863696993481817607137293272292657829912113907


#server's long term key
QSer_long = Point(0xc1bc6c9063b6985fe4b93be9b8f9d9149c353ae83c34a434ac91c85f61ddd1e9 , 0x931bd623cf52ee6009ed3f50f6b4f92c564431306d284be7e97af8e443e69a8c, curve)

#mes = {'ID':23813, 'H': h, 'S': s, 'LKEY.X': QCli_long.x, 'LKEY.Y': QCli_long.y}


####Register Long Term Key
print("Have you registered your LKEY?...", " yes or no?\n")
lkey_registered = input()
if(lkey_registered == "no"):

	mes = {'ID':stuID, 'H': h, 'S': s, 'LKEY.X': lkeyx, 'LKEY.Y': lkeyy}
	response = requests.put('{}/{}'.format(API_URL, "RegLongRqst"), json = mes)
	print(response.json())
	code = input()
	mes = {'ID':stuID, 'CODE': code}
	response = requests.put('{}/{}'.format(API_URL, "RegLong"), json = mes)
	print(response.json())


else:
	print("You already registered.\n")




registered = True
key_dict = {}
# EPHEMERAL KEY
if not registered:
	for i in range(0, 10):

		random.seed(78 + i)
		e_secret = random.randint(0, E.order-2) #Sa
		ekey = e_secret*P
		ekeyx = ekey.x
		ekeyy = ekey.y

		random.seed(47 + i)
		k = random.randint(0, E.order-2)
		ephemeral_sk = k
		R = k*P
		msg = str(ekeyx) + str(ekeyy)
		lower_r = (R.x) % n
		hashdata = bytearray(msg.encode()) + lower_r.to_bytes((lower_r.bit_length()+7)//8, byteorder='big')

		h_object = SHA3_256.new()
		h_object.update(data=hashdata)

		h = (int.from_bytes(h_object.digest(), byteorder='big'))% n
		s = ((secretkey*int.from_bytes(h_object.digest(), byteorder='big'))+k) % n

		#send ephemeral key to server
		mes = {'ID': stuID, 'KEYID': i , 'QAI.X': ekey.x, 'QAI.Y': ekey.y, 'Si': s, 'Hi': h}
		response = requests.put('{}/{}'.format(API_URL, "SendKey"), json = mes)
		print(response.json())

		key_dict["key"+str(i)] = {'sa': e_secret, 'ekeyx': ekeyx, 'ekeyy': ekeyy, 'S': s, 'H': h}

		print("i = ", i , "\n", "ekeyx = ", ekeyx, "\n", "ekeyy = ", ekeyy, "\n", "e_secret = ", e_secret, "\n" ,"s = " , s, "\n", "h = ", h, "\n")
		
else:
	reset_ek = input("Delete and re_register EK?... yes or no? ")
	if(reset_ek == "yes"):
		mes = {'ID': stuID, 'S': s, 'H': h}
		response = requests.get('{}/{}'.format(API_URL, "RstEKey"), json = mes)


		for i in range(0, 10):

			random.seed(78 + i)
			e_secret = random.randint(0, E.order-2) #Sa
			ekey = e_secret*P
			ekeyx = ekey.x
			ekeyy = ekey.y

			random.seed(47 + i)
			k = random.randint(0, E.order-2)
			ephemeral_sk = k
			R = k*P
			msg = str(ekeyx) + str(ekeyy)
			lower_r = (R.x) % n
			hashdata = bytearray(msg.encode()) + lower_r.to_bytes((lower_r.bit_length()+7)//8, byteorder='big')

			h_object = SHA3_256.new()
			h_object.update(data=hashdata)

			h = (int.from_bytes(h_object.digest(), byteorder='big'))% n
			s = ((secretkey*int.from_bytes(h_object.digest(), byteorder='big'))+k) % n

			#send ephemeral key
			mes = {'ID': stuID, 'KEYID': i , 'QAI.X': ekey.x, 'QAI.Y': ekey.y, 'Si': s, 'Hi': h}
			response = requests.put('{}/{}'.format(API_URL, "SendKey"), json = mes)
			print(response.json())

			key_dict["key"+str(i)] = {'sa': e_secret, 'ekeyx': ekeyx, 'ekeyy': ekeyy, 'S': s, 'H': h}

			print("i = ", i , "\n", "ekeyx = ", ekeyx, "\n", "ekeyy = ", ekeyy, "\n", "e_secret = ", e_secret, "\n" ,"s = " , s, "\n", "h = ", h, "\n")
			



use_preset = input("Use your last ephemeral values?... 'yes' or 'no' ")
if(use_preset == "yes"):
	print("using last values...")
	key_dict = {}

	i =  0 
	ekeyx =  102528309578888824996267748161584930797253996462430199738461492408841047272368 
	ekeyy =  96964975800446491017943978569398147809600492962657337227659761281196657179756 
	e_secret =  100925513402285245227264598877390757792184756567290463479492798132925700875220 
	s =  3303586088425744106514728208238518039153781009902734536220079850210170292675 
	h =  97633069284354319548778301551469711195696545783716796224265644527568026041843 
	key_dict["key"+str(i)] = {'sa': e_secret, 'ekeyx': ekeyx, 'ekeyy': ekeyy, 'S': s, 'H': h}

	i =  1 
	ekeyx =  17135788569537152611703956657266316938875369515063909960034045074391541273946 
	ekeyy =  81445009016488292499423118208316308254263254342107989146385117824223510860940 
	e_secret =  83800845813593517077027280063069757912929624827461288716501679191818415423533 
	s =  89103960061710268114436241821446196805161682728806181421362905736057513514761 
	h =  11926468279962865371492149215382902627186183864451373055434986691993309307733 
	key_dict["key"+str(i)] = {'sa': e_secret, 'ekeyx': ekeyx, 'ekeyy': ekeyy, 'S': s, 'H': h}


	i =  2 
	ekeyx =  73589247525613020339616980416950670588680762963211471939111616978930922966506 
	ekeyy =  56183818254315083570726063172066373450620567657283375876204257262749544040348 
	e_secret =  48724656234694639500240513703576691908862370122723935791338443242543255679259 
	s =  54401360268906054180425953799816646656503900647639989085471921200157967706517 
	h =  1898172804591124247259142905961582622666001049001086383628826829910117383910 
	key_dict["key"+str(i)] = {'sa': e_secret, 'ekeyx': ekeyx, 'ekeyy': ekeyy, 'S': s, 'H': h}


	i =  3 
	ekeyx =  100773349592480358574541931689434512446666447070372576912364699066915483751404 
	ekeyy =  65320742917466172320072127282165279429445955471794943135451381764893744547156 
	e_secret =  55455567547870248504244029642845819308327120865946343227382096258489402085258 
	s =  64187050591712418887791705060491508528835940622937387743756784080954343734124 
	h =  72045786097274702841354464155778889091835229347079218661670271011075538385309 
	key_dict["key"+str(i)] = {'sa': e_secret, 'ekeyx': ekeyx, 'ekeyy': ekeyy, 'S': s, 'H': h}


	i =  4 
	ekeyx =  48579717232331535051028610904240374893408051361933466210140697765856783377102 
	ekeyy =  30192845812962073886266267702026762310020812520663829137390462117051527703637 
	e_secret =  95478187922030471125816293095953671837562602358849110396888142473522938931187 
	s =  65264799554737004732681832375023068485452216565746012300661615268789623652325 
	h =  66273234789710064139574268879416332544818100081396252216378927632210595221101 
	key_dict["key"+str(i)] = {'sa': e_secret, 'ekeyx': ekeyx, 'ekeyy': ekeyy, 'S': s, 'H': h}


	i =  5 
	ekeyx =  46126762498265813324703321636273164780684201915850382144599097291342963795930 
	ekeyy =  72190922267475906112889829369674326718566120517674993305048056562503182286921 
	e_secret =  3983183122648515755889316165910892266273555691259585353904455368916978636584 
	s =  34716881569803620731779550646074786302676668493329184931677574033444772405498 
	h =  54284583025900105504710999231060556428331499208380865639978095921722829563913 
	key_dict["key"+str(i)] = {'sa': e_secret, 'ekeyx': ekeyx, 'ekeyy': ekeyy, 'S': s, 'H': h}


	i =  6 
	ekeyx =  102068212750480657941250958908386807363777020956670284174783996705760807833869 
	ekeyy =  69171400792360255483829300170991669664002421887141195225460077880738629580878 
	e_secret =  60409307759535690014813228631344851165971451765132211357386103315817577160671 
	s =  96002875104779433009246714831561710750731491980608990684807706291683581332472 
	h =  37894949497001846290382867392853140164370976443366689510246614652378240825204 
	key_dict["key"+str(i)] = {'sa': e_secret, 'ekeyx': ekeyx, 'ekeyy': ekeyy, 'S': s, 'H': h}


	i =  7 
	ekeyx =  110073802823048620189699154736372506530216542456786695060887192835185019259777 
	ekeyy =  32919848722941799330852857128386291556290693513912927325655797019015012856527 
	e_secret =  109485065184434522057450192962053380876201047649869394211673294218570237492955 
	s =  67030654051794745774587788577590044907335993737685648136391596395276998747396 
	h =  63545415846919303097291806768804605556644086453215711086021253979957858392899 
	key_dict["key"+str(i)] = {'sa': e_secret, 'ekeyx': ekeyx, 'ekeyy': ekeyy, 'S': s, 'H': h}


	i =  8 
	ekeyx =  59513931719145525737247508048935238302466258283316192450336119271282468292073 
	ekeyy =  65539611469346694398217717764370502416648062452323723786527678131534762162106 
	e_secret =  86051555336872904098043085722308749692563669607111910912315618437619777630606 
	s =  12020960758092198526820696181647651564470244636988250555881134990561249963564 
	h =  39794309230743043360400545294649381156260134823302313533069817835708842177206 
	key_dict["key"+str(i)] = {'sa': e_secret, 'ekeyx': ekeyx, 'ekeyy': ekeyy, 'S': s, 'H': h}


	i =  9 
	ekeyx =  49962349494474648821796658765765039506366870869051878541017836995851062949171 
	ekeyy =  60274825915425733120439087432150109917705284721887417948203319818815754649073 
	e_secret =  11832533262116137958687458636888392851733766834466849231376329381555835063096 
	s =  92092581203832824628662665853314873571066598580233490467162616958054743245802 
	h =  88317866784934674370384050702500866297879669311033804043566763191635939751367 
	key_dict["key"+str(i)] = {'sa': e_secret, 'ekeyx': ekeyx, 'ekeyy': ekeyy, 'S': s, 'H': h}


	print("Dictionary updates with the last values...\n")


else:
	print("continuing...")




"""




"""


random.seed(98)
k = random.randint(0, E.order-2)
sign_sk = k
R = k*P
lower_r = (R.x) % n
msg = bytearray('23813'.encode())
hashdata = msg + lower_r.to_bytes((lower_r.bit_length()+7)//8, byteorder='big')

h_object = SHA3_256.new()
h_object.update(data=hashdata)

h = (int.from_bytes(h_object.digest(), byteorder='big'))% n
s = ((secretkey*int.from_bytes(h_object.digest(), byteorder='big'))+k) % n

print("receiving messeages...")
#Receiving Messages
for i in range(0, 5):
	mes = {'ID_A': stuID, 'S': s, 'H': h}
	response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json = mes)
	print(response.json())
	res = response.json()
	parsed_res = list(res.values())
	
	
	k_index = parsed_res[1]
	print("current i = ", k_index)
	c_text = parsed_res[2]
	Qj_x = parsed_res[3]
	Qj_y = parsed_res[4]
	Q_b = Point(Qj_x, Qj_y, curve)
	T = key_dict["key" + str(k_index)]['sa'] * Q_b
	U = str(T.x) + str (T.y) + "NoNeedToRunAndHide"
	hdata = bytearray(U.encode())
	this_index = "key" + str(k_index)
	
	K_session = SHA3_256.new()
	K_session.update(data=hdata)
	key = int.from_bytes(K_session.digest(), byteorder='big')  #int version of session key

	
	ciphertext = c_text.to_bytes((c_text.bit_length()+7)//8, byteorder='big')
	
	hmac = ciphertext[-32:]


	kmac = SHA3_256.new()
	kmac.update(data=K_session.digest())

	hmac_data = ciphertext[8:-32]
	v_hmac = HMAC.new(key=kmac.digest(), digestmod=SHA256)
	v_hmac.update(msg=hmac_data)
	try:
		v_hmac.verify(hmac)
		print("The message is authentic")


	except ValueError:
		print("The message or the key is wrong")


	#decrypt messages

	s_cipher = AES.new(key.to_bytes((key.bit_length()+7)//8, byteorder='big'), AES.MODE_CTR, nonce=ciphertext[0:8])
	dtext = s_cipher.decrypt(ciphertext[8:-32])

	



	print("dtext: ", dtext.decode('ISO-8859-1'), "\n")
	#send decrypted messages to server
	mes = {'ID_A': stuID, 'DECMSG': str(dtext.decode('ISO-8859-1'))}
	response = requests.put('{}/{}'.format(API_URL, "Checker"), json = mes)
	print(response.json())


#send decrypted messages to server
#mes = {'ID_A': stuID, 'DECMSG': h}
#response = requests.put('{}/{}'.format(API_URL, "Checker"), json = mes)


###delete ephemeral keys
#mes = {'ID': stuID, 'S': s, 'H': h}
#response = requests.get('{}/{}'.format(API_URL, "RstEKey"), json = mes)



###########DELETE LONG TERM KEY
# If you lost your long term key, you can reset it yourself with below code.

# First you need to send a request to delete it.
registered = input("Do you want to re-register LKEY?... type 'yes' or 'no'")
if(registered == "yes"): 
	mes = {'ID': stuID}
	response = requests.get('{}/{}'.format(API_URL, "RstLongRqst"), json = mes)

	#Then server will send a verification code to your email. 
	# Send this code to server using below code
	mes = {'ID': stuID, 'CODE': code}
	response = requests.get('{}/{}'.format(API_URL, "RstLong"), json = mes)

else:
	print("Your keys won't reset.")

#Now your long term key is deleted. You can register again. 

