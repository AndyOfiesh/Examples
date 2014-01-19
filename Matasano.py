'''
Created on Jun 15, 2013

@author: Andy
'''
from encodings.base64_codec import base64_decode
BASE64CHARS  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
BASE16CHARS  = '0123456789abcdef'


def intToHex(i):
   h = hex(i)[2:]
   if isinstance(i,long):
      h = h[:-1]
   if len(h)%2 == 1:
      h = '0'+h
   return h

def hexToInt(h):
   return(int(h, 16))
def binaryToBase64(binaryString):
   n = 0
   for char in binaryString:
      n *= 256
      n += ord(char)
   base64 = ''
   while n > 0:
      n, remainder = divmod(n, 64)
      base64 = BASE64CHARS[remainder] + base64
   return base64

def base64ToBinary(base64):
   n = 0
   for char in base64:
      n = n * 64 + BASE64CHARS.index(char) if char in BASE64CHARS else n
   binaryOut = ''
   while n > 0:
      n,remainder = divmod(n,256)
      binaryOut = chr(remainder) + binaryOut
   return binaryOut

def hexToBinary(hexString):
   return hexString.decode('hex_codec')

def binaryToHex(binaryString):
   return binaryString.encode('hex_codec')

def hexToBase64(hexInput):
   return binaryToBase64(hexToBinary(hexInput))

def base64ToHex(base64):
   return binaryToHex(base64ToBinary(base64))

def problem1():
   print "Problem 1:"
   hexInput = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
   print "Hex input: ", hexInput
   base64Answer = hexToBase64(hexInput)
   print "Base 64: ", base64Answer
   print "Hex output: ", base64ToHex(base64Answer)
   print "\n\n"
    
def xorHex(hexString1, hexString2):
   result = ''
   if len(hexString1) == len(hexString2):
      i1 = hexToInt(hexString1)
      i2 = hexToInt(hexString2)
      result = intToHex(i1^i2)
   return result
    
def problem2():
   problem2Input1 = '1c0111001f010100061a024b53535009181c'
   problem2Input2 = '686974207468652062756c6c277320657965'
   print "Problem 2:"
   print "Input1: ", problem2Input1
   print "Input2: ", problem2Input2
   print xorHex(problem2Input1, problem2Input2)
    
problem3Input = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'

letterScore = {'a':812, 
               'b':149,
               'c':271,
               'd':432,
               'e':1202,
               'f':230,
               'g':203,
               'h':592,
               'i':731,
               'j':10,
               'k':69,
               'l':398,
               'm':261, 
               'n':695,
               'o':768,
               'p':182,
               'q':11,
               'r':602,
               's':628, 
               't':910,
               'u':288,
               'v':111,
               'w':209,
               'x':17,
               'y':211,
               'z':7,
               ' ':1225, '0':100, '1':100, '2':100, '3':100, '4':100, '5':100, '6':100, '7':100, '8':100, '9':100,
               '.':100, ',':100, '?':50, '!':50, ':':50, ';':50, '\"':50, '\'':50, '(':50, ')':50, '`':50}


getScore = lambda c: letterScore[c.lower()] if c in letterScore else -100

scoreString = lambda inputString: sum([getScore(c) for c in inputString])

def xorHexWithInt(inputBinaryString, inputInt):
   result = ''
   for char in inputBinaryString:
      result = result + chr(ord(char)^inputInt)
   return result

def decryptString(inputString):
   result = ''
   resultScore = 0
   for i in range(255):
      tryString = xorHexWithInt(inputString, i)
      tryScore = scoreString(tryString)
      if tryScore > resultScore:
         result = tryString
         key = i
         resultScore = tryScore
   return result, chr(key), resultScore
        

def problem3():   
   print "Problem 3:"
   decryptedString, key, resultScore = decryptString(hexToBinary(problem3Input))
   print "Key: ", key
   print "Decrypted String: ", decryptedString
    
def problem4():
   print "Problem: 4:"
   f = open('problem4data.txt', 'r')
   highScore = 0
   for line in f:
      decryptedString, key, resultScore = decryptString(hexToBinary(line.strip('\n')))
      if (resultScore > highScore):
            highScore = resultScore
            bestDecryptedString = decryptedString
   print "Key: ", key
   print "Decrypted String: ", bestDecryptedString

problem5Input = "Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal"
problem5Key = "ICE"

repeatingXorEncrypt = lambda inputString, key: "".join([intToHex(ord(inputString[i])^ord(key[i%len(key)])) for i in range(len(inputString))])
def problem5():
   print "Problem 5:"
   print repeatingXorEncrypt(problem5Input,problem5Key)


recursivelyCountBits = lambda inputVector: (recursivelyCountBits(divmod(inputVector[0], 2)) if inputVector[0] > 0 else 0) + inputVector[1]

calculateCharHammingDistance = lambda char1, char2: recursivelyCountBits(divmod(ord(char1)^ord(char2),2))

calculateStringHammingDistance = lambda string1, string2: sum([calculateCharHammingDistance(char1, char2) for char1, char2 in zip(string1,string2)])

def findKeySizes(inputString, minKeySize, maxKeySize):
   keyList = []
   for i in range(minKeySize,maxKeySize+1):
      n = len(inputString)/i-2
      normalizedDistance = sum([calculateStringHammingDistance(inputString[j*i:(j+1)*i], inputString[(j+1)*i:(j+2)*i])
                                  for j in range(n)])*1000/(n*i)
      keySizeScoreMap = i,normalizedDistance
      keyList.append(keySizeScoreMap)
   keyList.sort(key=lambda tup: tup[1])   
   return keyList


# def transposeBlocks(inputString, keySize, offset):
#    result = "".join([inputString[i] for i in range(offset, len(inputString), keySize)])
#    return result

def repeatingXorDecrypt(inputString, keySize):
   tResult = [decryptString(inputString[i::keySize])[0] for i in range(keySize)]
   result = []
   for j in range(len(tResult[0])):
      result.extend([tResult[i][j] if j < len(tResult[i]) else "" for i in range(keySize)])
   return "".join(result)

def problem6():
   print "Problem 6:"
   f = open('problem6data.txt', 'r')
   inputString = "".join([base64_decode(line.strip())[0] for line in f])
   keySizeList = findKeySizes(inputString, 2, 40)
   result = repeatingXorDecrypt(inputString, keySizeList[0][0])
   print result







