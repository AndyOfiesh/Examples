from utilities.ArmoryUtils import LITTLEENDIAN, int_to_hex, hex_to_binary, \
   binary_to_hex, hex_to_int, sha256

getBitDisplay = lambda bits: ''.join(['X' if b>0 else '_' for b in bits])
orBits        = lambda a,b:  [a[i] | b[i] for i in range(len(a))]
andBits       = lambda a,b:  [a[i] & b[i] for i in range(len(a))]

##### INT/BINARYSTR #####
def int_to_binary(i, widthBytes=0, endOut=LITTLEENDIAN):
   """
   Convert integer to binary.  Default behavior is use as few bytes
   as necessary, and to use little-endian.  This can be changed with
   the two optional input arguemnts.
   """
   h = int_to_hex(i,widthBytes)
   return hex_to_binary(h, endOut=endOut)

def binary_to_int(b, endIn=LITTLEENDIAN):
   """
   Converts binary to integer (or long).  Interpret as LE by default
   """
   h = binary_to_hex(b, endIn, LITTLEENDIAN)
   return hex_to_int(h)

class BloomFilter(object):
   def __init__(self, numHashFunc, numBits):
      self.bitArray = [0]*numBits
      def getBitsForData(self, theData):
         dataBits = [0]*len(self.bitArray)
         for i in range(self.numFunc):
            toHash = theData + int_to_binary(i, widthBytes=4)
            bitNum = binary_to_int(sha256(toHash)) % len(self.bitArray)
            dataBits[bitNum] = 1
         return dataBits
 
   def addDataToFilter(self, theData, verbose=False):
      dataBits = self.getBitsForData(theData)
      oldSelf  = self.bitArray[:]
      self.bitArray = orBits(dataBits, self.bitArray)
      if(verbose):
         print 'State after %s: ' % theData.ljust(6), getBitDisplay(self.bitArray)

   def checkInclusion(self, theData):
      dataBits = self.getBitsForData(theData)
      return (sum(dataBits) == sum(andBits(dataBits, self.bitArray)))



bloom = BloomFilter(5, 30)
bloom.addDataToFilter('Alan',  True)
bloom.addDataToFilter('Marie', True)
bloom.addDataToFilter('Andy',  True)
bloom.addDataToFilter('Amy',   True)
bloom.addDataToFilter('Dave',  True)
bloom.addDataToFilter('Erin',  True)

def printInclusion(x):
   isTrue = bloom.checkInclusion(x)
   print '   ', ('"'+x+'"').ljust(10), ('MaybeIn' if isTrue else 'DefinitelyNotIn')

print 'All these strings should pass the bloom filter'
printInclusion('Alan')
printInclusion('Marie')
printInclusion('Andy')
printInclusion('Amy')
printInclusion('Dave')
printInclusion('Erin')
print 'Some non-elements that might pass but should mostly be rejected'
printInclusion('George')
printInclusion('Matt')
printInclusion('Chris')
printInclusion('Barry')
printInclusion('Monty')
printInclusion('Euler')
printInclusion('Wendy')
printInclusion('Craig')
printInclusion('Stacy')