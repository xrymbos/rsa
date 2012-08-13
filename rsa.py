# COSC413 Assignment 1
# Jamie McCloskey
# RSA encryption, decryption, and authentication
# Reads plaintext from the file text.txt and performs a demonstration of RSA with random key pairs

import random

PRIME_TRIALS = 20 #number of times we run the composite-checking algorithm
                  #We have about (1/4)^20 chance of false positives
BLOCK_SIZE = 20   #The plaintext message will be split into chunks of this size before encryption
MAX_CHAR = 256    #Number of different characters that we can encrypt
DIGITS = 50       #Number of decimal digits to use for p and q
FILE = "text.txt" #File to read plaintext from


def modpow(base, exponent, mod):
	#Computes base^exponent mod mod using repeated squaring
	ans = 1
	index = 0
	while(1 << index <= exponent):
		if(exponent & (1 << index)):
			ans = (ans * base) % mod
		index += 1
		base = (base * base) % mod
	return ans

def euclid(a, b):
	#Finds x and y such that ax + by = gcd(a,b)
	#Returns the tuple (gcd(a,b), x, y)
	y = 0
	z = 1
	lasty = 1
	lastz = 0
	while(b != 0):
		q = a / b
		r = a % b
		a = b
		b = r
		tmp = y
		y = lasty - q*y
		lasty = tmp
		tmp = z
		z = lastz - q*z
		lastz = tmp
	return (a, lasty, lastz)

def isWitness(a, s, d, n):
	#Is a a Miller-Rabin witness to the compositeness of n?
	x = modpow(a, d, n);
	if(x == 1 or x == n-1):
		return False
	for r in xrange(s):
		x = (x * x) % n
		if(x == 1):
			return True
		if(x == n-1):
			return False
	return True

def isPrime(n):
	#Determines if a number n is probably prime, using the Miller-Rabin test.
	if(n == 2 or n == 3):
		return True
	if(n < 2):
		return False
	if(n % 2 == 0):
		return False
	s = 0
	d = n-1
	while(d % 2 == 0):
		d /= 2
		s += 1
	for i in xrange(PRIME_TRIALS):
		a = random.randint(2, n-2)
		if(isWitness(a, s, d, n)):
			return False
	return True

def slowPrime(n):
	#Slow trial division primality testing algorithm
	#Always correct
	if(n <= 1):
		return False
	x = 2
	while(x*x <= n):
		if(n % x == 0):
			return False
		x += 1
	return True

def getPrime(digits):
	#Returns a randomly chosen prime number with a specified number of decimal digits
	while(True):
		x = random.randint(10**(digits-1), 10**(digits) - 1)
		if(isPrime(x)):
			return x

def strToNum(s):
	#Converts a string of length BLOCK_SIZE to an integer
	return sum([(MAX_CHAR**i)*ord(c) for i, c in enumerate(s)])

def numToStr(n):
	#Performs the inverse operation of strToNum
	s = ""
	for i in xrange(BLOCK_SIZE):
		s += chr(n % MAX_CHAR)
		n /= MAX_CHAR
	return s.replace("\0", "")

def encode(s):
	#Encodes s to a list of numbers.
	#Padding characters are added to the end of s until it is a multiple of BLOCK_SIZE characters.
	while(len(s) % BLOCK_SIZE != 0):
		s += '\0'
	chunks = [s[i:i+BLOCK_SIZE] for i in range(0, len(s), BLOCK_SIZE)]
	return [strToNum(chunk) for chunk in chunks]

def decode(numbers):
	#Inverse operation of encode
	#Converts a list of numbers to a string
	return "".join([numToStr(n) for n in numbers])

def generateKey():
	#Generates a random public/private RSA key pair
	p = getPrime(DIGITS)
	q = getPrime(DIGITS)
	n = p*q
	phi = (p-1)*(q-1)
	while(True):
		e = random.randint(2, phi-1)
		(gcd, d, y) = euclid(e, phi)
		if(gcd == 1):
			break
	while(d < 0):
		d += phi
	return (p, q, n, e, d)

def encrypt(numbers, e, n):
	return [modpow(m, e, n) for m in numbers]

def wait():
	print "Press Enter to continue."
	raw_input()

def doRSA(s):
	#Encrypts and decrypts s using the RSA algorithm
	numbers = encode(s)
	print "Testing encryption..."
	print "Generating keys..."
	(p, q, n, e, d) = generateKey()
	print "Key setup completed:"
	print "p = %d, q = %d" % (p,q)
	print "n = %d" % n
	print "e = %d\nd = %d" % (e, d)
	wait()
	print "Performing encryption on following message:\n-------------"
	print s
	wait()
	print "-------------\nString encoded to following list of integers:"
	print numbers
	wait()
	encrypted = encrypt(numbers, e, n)
	print "Encrypted message is as follows:"
	print encrypted
	wait()
	decrypted = encrypt(encrypted, d, n)
	recieved = decode(decrypted)
	print "Decrypted message is as follows:\n-------------"
	print recieved
	print "-------------"
	if(recieved == s):
		print "Success! Recieved message is identical!"
	else:
		print "Something went wrong! Recieved message was garbled!"
	wait()
	print "\nNow testing authentication. Generating second key pair..."
	(p2, q2, n2, e2, d2) = generateKey()
	print "Generated second key:"
	print "p2 = %d, q2 = %d" % (p2,q2)
	print "n2 = %d" % n2
	print "e2 = %d\nd2 = %d" % (e2, d2)
	wait()
	print "Sending a signed and encrypted message from user with key (n, e, d) to user with key (n2, e2, d2)..."
	#we sign with our private key and then encrypt with the destination's public key
	encryptionOps = [(d, n), (e2, n2)] #Operations required to encrypt
	#they decrypt with their private key and verify with our public key
	decryptionOps = [(d2, n2), (e, n)] #Operations to decrypt
	#We need to encrypt with the smaller n first
	if(n2 < n):
		encryptionOps.reverse()
		decryptionOps.reverse()
	encrypted = numbers
	for op in encryptionOps:
		encrypted = encrypt(encrypted, op[0], op[1])
	print "Encrypted and signed message is as follows:"
	print encrypted
	wait()
	decrypted = encrypted
	for op in decryptionOps:
		decrypted = encrypt(decrypted, op[0], op[1])
	recieved = decode(decrypted)
	print "Decrypted message is as follows:\n-------------"
	print recieved
	print "-------------"
	if(recieved == s):
		print "Success! Recieved message is identical!"
	else:
		print "Something went wrong, or the sender is not who he says he is"

plaintext = open(FILE, "r").read()
doRSA(plaintext)





