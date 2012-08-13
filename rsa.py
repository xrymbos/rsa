import random

PRIME_TRIALS = 20 #number of times we run the composite-checking algorithm
                  #We have about (1/4)^20 chance of false positives
BLOCK_SIZE = 20 #The plaintext message will be split into chunks of this size before encryption
MAX_CHAR = 256 #Number of different characters that we can encrypt


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

def isWitness(a, s, d, n):
	#Is a a Miller-Rabin witness to the compositeness of n?
	#print "a is %d" % a
	x = modpow(a, d, n);
	if(x == 1 or x == n-1):
		return False
	for r in xrange(s):
		x = (x * x) % n
		if(x == 1):
			#print "Failed test"
			return True
		if(x == n-1):
			return False
	#print "Failed test"
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
	#print "d is %d, s is %d" % (d, s)
	for i in xrange(PRIME_TRIALS):
		a = random.randint(2, n-2)
		if(isWitness(a, s, d, n)):
			return False
	return True

def slowPrime(n):
	#slow trial division primality testing algorithm
	#always correct
	if(n <= 1):
		return False
	x = 2
	while(x*x <= n):
		if(n % x == 0):
			return False
		x += 1
	return True

def getPrime(digits):
	#Returns a randomly chosen prime number with a specified number of digits
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





