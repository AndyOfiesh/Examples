'''
Created on Jul 8, 2013

@author: Andy
'''
from armoryengine.ArmoryUtils import binary_to_hex, binary_to_int, BIGENDIAN, hex_to_int, \
   LITTLEENDIAN, hash256, hex_to_binary, \
   int_to_hex, BTC_HOME_DIR,  prettyHex, hash160, ripemd160, \
   hash160_to_addrStr, addrStr_to_hash160, coin2str, ONE_BTC, binary_to_base58
from armoryengine.BinaryUnpacker import *
from collections import namedtuple
from pickle import BINUNICODE
from string import find
from time import gmtime, strftime
from twisted.conch.insults.window import cursor
import os
from armoryengine.Transaction import *

def getFileSize(f):
   pos = f.tell()
   # Go to the end to get the file length
   f.seek(0,2)
   result = f.tell()
   f.seek(pos)
   return result


MAGIC_HEX_STRING = "f9beb4d9"
MAGIC_NUMBER_LENGTH = 4
VERSION_LENGTH = 4
BLOCK_SIZE_LENGTH = 4
TX_OUT_HASH_LENGTH = 32
TX_OUT_INDEX_LENGTH = 4
SEQUENCE_LENGTH = 4
LOCKTIME_LENGTH = 4
SATOSHI_LENGTH = 8
HEADER_LENGTH = 80
HEX_32_BYTE_0 = "0000000000000000000000000000000000000000000000000000000000000000"
BIN_32_BYTE_0 = hex_to_binary(HEX_32_BYTE_0)
HEX_32_BYTE_ALL_F = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
DIFFICULTY_NUMERATOR = 0x00000000FFFF0000000000000000000000000000000000000000000000000000

getHighestTarget = lambda bits: float(hex_to_int(binary_to_hex(bits, BIGENDIAN)[2:8]) * 2**(8*(hex_to_int(binary_to_hex(bits, BIGENDIAN)[:2]) - 3)))

def calculateDifficulty(bits):
   return DIFFICULTY_NUMERATOR / getHighestTarget(bits)

def parseBlockHeader(blkHdrBinary):
   binunpack = BinaryUnpacker(blkHdrBinary)
   return BlockHeader(binunpack.get(UINT32),
                      binunpack.get(BINARY_CHUNK, 32),
                      binunpack.get(BINARY_CHUNK, 32),
                      binunpack.get(UINT32),
                      binunpack.get(UINT32),
                      binunpack.get(UINT32))

blkCounter = -1

MERKLE_ROOT_TEST_RESULT = "d6f226837f442e34974d01825cbac711f4c358d1f564747d3d7203a2d4e94619"

dHashList = lambda lst: [hash256(data) for data in lst]

evenList = lambda lst: lst if len(lst) % 2 == 0 else lst + lst[len(lst) - 1:len(lst)]

foldEvenList = lambda lst: [lst[i] + lst[i+1] for i in range(0, len(lst), 2)]

foldList = lambda lst: foldEvenList(evenList(lst))

def computeMerkleRoot(lst, merkleCounter=0):
   # print binary_to_hex(lst[-1])
   if merkleCounter:
      for item in lst:
         print merkleCounter, binary_to_hex(item)
         merkleCounter += 1
      print
   return computeMerkleRoot(dHashList(foldList(lst)), merkleCounter) if len(lst) > 1 else lst[0]


def testMerkle():
   txAHash    = hex_to_binary('aa'*32)
   txBHash    = hex_to_binary('bb'*32)
   txCHash    = hex_to_binary('cc'*32)
   answer = hex_to_binary('d6f226837f442e34974d01825cbac711f4c358d1f564747d3d7203a2d4e94619')
   print 'PASSED' if computeMerkleRoot([txAHash, txBHash, txCHash], 1) == answer else 'FAILED'


def getNextBlock(f):   
   global blkCounter
   f.seek(MAGIC_NUMBER_LENGTH, 1)
   blkSize = binary_to_int(f.read(BLOCK_SIZE_LENGTH), LITTLEENDIAN)
   result = None
   if blkSize > 0:
      binunpack = BinaryUnpacker(f.read(blkSize))
      blkHdrBinary = binunpack.get(BINARY_CHUNK, HEADER_LENGTH)
      blkHdr = parseBlockHeader(blkHdrBinary)
      blkCounter += 1
      txCount = binunpack.get(VAR_INT)
      txBinary = binunpack.get(BINARY_CHUNK, binunpack.getRemainingSize())
      txOffsetList = getTxOffsetList(txBinary, txCount)
      txList = []
      for i in range(len(txOffsetList)):
         tx = txBinary[txOffsetList[i]:txOffsetList[i+1] if i < len(txOffsetList) - 1 else len(txBinary)]
         txList.append(getTx(tx, blkCounter))
      result = Block(blkCounter, blkSize,
                   blkHdr,
                   txCount,
                   txBinary,
                   txOffsetList,txList)
   else:
      f.seek(0,2)
   return result

def parseBlockFile(path):
   txCount = 0
   blkList = []
   with open(path, 'rb') as f:
      fSize = getFileSize(f)
      while f.tell() < fSize and len(blkList) < 10000:
         blk = getNextBlock(f)
         if blk != None:
            blkList.append(blk)
            txCount += blk.txCount
   return blkList, txCount

def parseBlockDir(dirList):
   txCount = 0
   allBlkList = []
   for fname in dirList:
      blkList, fileTxCount = parseBlockFile(fname)
      txCount += fileTxCount
      allBlkList.extend(blkList)
   return txCount, allBlkList
      
def findLowestHash(dirList):
   lowestHashInt = hex_to_int(HEX_32_BYTE_ALL_F)
   lowestHashBlkNum = -1
   for fname in dirList:
      blkList, fileTxCount = parseBlockFile(fname)
      for blk in blkList:
         hashInt = hex_to_int(blk.blkHdr.prevHash)
         if hashInt != 0 and hashInt < lowestHashInt:
            lowestHashInt = hashInt
            lowestHashBlkNum = blk.blkNum - 1
   return int_to_hex(lowestHashInt, 32), lowestHashBlkNum
         
def exercise1():
   print "Block Chain Parser Exercise #1: "
   txCount,blkList = parseBlockDir([os.path.join(BTC_HOME_DIR, 'blocks', 'blk00001.dat')])
   print "Number of blocks: ", blkCounter
   print "Number of Transactions: ", txCount

def exercise2():
   print "Block Chain Parser Exercise #2: "
   print findLowestHash([os.path.join(BTC_HOME_DIR, 'blocks', 'blk00001.dat')])
   
def exercise3():
   print "Block Chain Parser Exercise #3: "
   txCount,blkList = parseBlockDir([os.path.join(BTC_HOME_DIR, 'blocks', 'blk00001.dat')])
   for blk in blkList:
      if blk.blkNum % 2016 == 1:
         print blk.blkNum, calculateDifficulty(blk.blkHdr.bits)
         
def getStart(blk, i):  
   return blk.txOffsetList[i]    

def getEnd(blk, i):
   return blk.txOffsetList[i+1]  if i + 1 < blk.txCount else len(blk.txBinary)
                          
computeMerkleRootOfBlock = lambda blk: computeMerkleRoot([hash256(blk.txBinary[getStart(blk, i): getEnd(blk, i)]) for i in range(blk.txCount)], 0)

def exercise4():
   print "Block Chain Parser Exercise #4: "
   blockList = parseBlockDir([os.path.join(BTC_HOME_DIR, 'blocks', 'blk00001.dat')])[1]
   for blk in blockList:
      print "Block: ", blk.blkNum, ": Difficulty - ", 
      # print "VERIFIED" if binary_to_int(dHash(blk.blkHdrBinary), BIGENDIAN) < getHighestTarget(blk.blkHdr.bits) else "FAIL",
      print " Merkle Root - ",
      merkleRoot = computeMerkleRootOfBlock(blk)
      print "VERIFIED" if  merkleRoot == blk.blkHdr.merkleHash else "FAIL"
      prevBlk = blk

def exercise5():
   print "Block Chain Parser Exercise #5: "
   blockList = parseBlockDir([os.path.join(BTC_HOME_DIR, 'blocks', 'blk00001.dat')])[1]
   gapList = []
   lastTime = 0
   for blk in blockList:
      if (lastTime > 0):      
         if blk.blkHdr.time - lastTime < 400000 :
            gapList.append(blk.blkHdr.time - lastTime)
         if blk.blkHdr.time - lastTime < 0 or blk.blkHdr.time - lastTime > 80000:
            print blk, lastTime
      lastTime = blk.blkHdr.time
      print "Block ", blk.blkNum, "Time Stamp: ", blk.blkHdr.time, strftime("%d %b %Y %H:%M:%S",gmtime(blk.blkHdr.time))
   print "Low = ", min(gapList)
   print "High = ", max(gapList)
   print "Average = ", sum(gapList)/float(len(gapList))
   

def getTxOffsetList(txListBinary, txCount):
   binunpack = BinaryUnpacker(txListBinary)
   txOffsetList = []
   for i in range(txCount):
      txOffsetList.append(binunpack.getPosition())
      binunpack.advance(VERSION_LENGTH)
      txInCount =  binunpack.get(VAR_INT)
      for j in range(txInCount):
         binunpack.advance(TX_OUT_HASH_LENGTH + TX_OUT_INDEX_LENGTH)
         sigScriptLength = binunpack.get(VAR_INT)
         binunpack.advance(sigScriptLength + SEQUENCE_LENGTH)
      txOutCount  = binunpack.get(VAR_INT)
      for k in range(txOutCount):
         binunpack.advance(SATOSHI_LENGTH)
         scriptLength =  binunpack.get(VAR_INT)
         binunpack.advance(scriptLength)
      binunpack.advance(LOCKTIME_LENGTH)
   return txOffsetList

PAY_TO_PUBLIC_KEY = 'Pay-to-public-key'
PAY_TO_PUBKEY_HASH = 'Pay-to-pubkey-hash'
PAY_TO_SCRIPT_HASH = 'Pay-to-script-hash'
MULTISIGNATURE = 'Multisignature'
P2POOL_LAST_TX_OUT_OP_CODE = 37
PAY_TO_POOL_LAST_TX_OUT = 'Pay-to-pool-last-tx-out'
UNKNOWN = 'Unknown'


def getTx(tx, blkNum):
   binunpacker = BinaryUnpacker(tx)
   txData = Tx(hash256(tx), binunpacker.get(UINT32),[], [])
   txInCount = binunpacker.get(VAR_INT)
   for i in range(txInCount):
      outPoint = OutPoint(binunpacker.get(BINARY_CHUNK, TX_OUT_HASH_LENGTH),binunpacker.get(UINT32), blkNum)
      txInLength = binunpacker.get(VAR_INT)
      script = binunpacker.get(BINARY_CHUNK, txInLength)
      sequence = binunpacker.get(UINT32)
      txData.txInList.append(TxIn(outPoint, script, sequence))
   txOutCount = binunpacker.get(VAR_INT)   
   for j in range(txOutCount):
      value = binunpacker.get(UINT64)
      scriptLength = binunpacker.get(VAR_INT)
      if scriptLength > 0:
         script = binunpacker.get(BINARY_CHUNK,scriptLength)
         opcode = binary_to_int(script[:1])
         if opcode < 75 and len(script)==2+opcode and binary_to_int(script[1+opcode:], BIGENDIAN) == OP_CHECKSIG:
            txOutType = PAY_TO_PUBLIC_KEY
         elif opcode == OP_DUP and binary_to_int(script[-2]) == OP_EQUALVERIFY and binary_to_int(script[-1]) == OP_CHECKSIG:
            txOutType = PAY_TO_PUBKEY_HASH 
         elif opcode == OP_HASH160 and binary_to_int(script[1]) == 20 and binary_to_int(script[-1]) == OP_EQUAL:
            txOutType = PAY_TO_SCRIPT_HASH
         elif opcode == P2POOL_LAST_TX_OUT_OP_CODE and len(script) == 1 + opcode:
            txOutType = PAY_TO_POOL_LAST_TX_OUT
         elif opcode in [OP_1,OP_2,OP_3] and binary_to_int(script[-1]) == OP_CHECKMULTISIG:
            txOutType = MULTISIGNATURE
         else:
            txOutType = UNKNOWN  
      else:
         script = None
         txOutType = None
         j = txOutCount
      txData.txOutList.append(TxOut(j, value, script, txOutType))
   return txData
         
def exercise6():
   print "Block Chain Parser Exercise #6: " 
   blockList = parseBlockDir([os.path.join(BTC_HOME_DIR, 'blocks', 'blk00000.dat')])[1]

def recordHistory(blkList, testHash):
   result = []
   for blk in blkList:
      for tx in blk.txList:
         for txOut in tx.txOutList:
            if PAY_TO_PUBLIC_KEY == txOut.txOutType:
               # skip the push command at the beginning and OP_CHECKSIG at the end
               addr = txOut.script[1:-1]
               if binary_to_hex(hash160(addr)) == testHash:
                  result.append(txOut)
                  print blk.blkNum, coin2str(txOut.value, 4)
         
         
TEST_HASH160 = '11b366edfc0a8b66feebae5c2e25a7b6a5d1cf31'
TEST_BASE58 = '12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S'
TEST_ARMORY = '1ArmoryXcfq7TnCSuZa9fQjRYwJ4bkRKfv'

def hw4Exercise1():
   print "Block Chain Parser HW #4 Exercise #1: " 
   blkList = parseBlockDir([os.path.join(BTC_HOME_DIR, 'blocks', 'blk00000.dat')])[1]
   testAddrHistory = recordHistory(blkList, TEST_HASH160)

TxOut = namedtuple('TxOut', ['txOutIndex', 'value', 'script', 'txOutType'])
TxIn = namedtuple('TxIn', ['outpoint', 'script','sequence'])
Tx = namedtuple('Tx', ['txHash', 'version', 'txInList', 'txOutList'])
Block = namedtuple('Block', ['blkNum', 'blkSize', 'blkHdr', 'txCount', 'txBinary', 'txOffsetList', 'txList'])
BlockHeader = namedtuple('BlockHeader', ['version', 'prevHash', 'merkleHash',
                                       'time', 'bits', 'nonce' ])

OutPoint = namedtuple('OutPoint', ['txHash', 'txOutIndex', 'blkNum'])
TxIOPair = namedtuple('TxIOPair', ['txOut', 'txIn', 'totalAccumulated', 'balance'] )
blkFileNameList = [os.path.join(BTC_HOME_DIR, 'blocks', 'blk%05d.dat' % i)  for i in range(0,73)]
totalAccumulated = 0
balance = 0

def isForAddr(addrHash, txOut):
   if PAY_TO_PUBLIC_KEY == txOut.txOutType:
      # skip the push command at the beginning and OP_CHECKSIG at the end
      result = hash160(txOut.script[1:-1]) == addrHash
   elif PAY_TO_PUBKEY_HASH == txOut.txOutType:
      # skip OP_DUP, OP_HASH160, and push command (0x14) to start and OP_EQUALVERIFY and OP_CHECKSIG at the end
      result = txOut.script[3:-2] == addrHash
   else:
      result = False
   return result

def addBlockToHistory(addrHash, addrHistory, blk):
   global totalAccumulated
   global balance
   for tx in blk.txList:
      for txOut in tx.txOutList:
         if isForAddr(addrHash, txOut):
            totalAccumulated += txOut.value
            balance += txOut.value
            addrHistory[OutPoint(tx.txHash, txOut.txOutIndex, blk.blkNum)] = TxIOPair(txOut, None, totalAccumulated, balance)
      for txIn in tx.txInList:
         unspentKeyList = [key for key in addrHistory if addrHistory[key].txIn == None]
         for key in unspentKeyList:
            if txIn.outpoint.txHash == key.txHash and txIn.outpoint.txOutIndex == key.txOutIndex:
               spentTxOut = addrHistory[key].txOut
               balance -= spentTxOut.value
               addrHistory[OutPoint(tx.txHash, spentTxOut.txOutIndex, blk.blkNum)] = TxIOPair(spentTxOut, txIn, totalAccumulated, balance)

def addFileToHistory(addrHash, addrHistory, blkFileName):
   print blkFileName
   with open(blkFileName, 'rb') as f:
      fSize = getFileSize(f)
      while f.tell() < fSize:
         blk = getNextBlock(f)
         if blk != None:
            addBlockToHistory(addrHash, addrHistory, blk)
            

def getAddrHistory(addrHash):
   addrHistory = {}
   for blkFileName in blkFileNameList:
      addFileToHistory(addrHash, addrHistory, blkFileName)
   return addrHistory  

def hw4Exercise2():
   print "Block Chain Parser HW #4 Exercise #2: "
   addrHistory = getAddrHistory(addrStr_to_hash160(TEST_ARMORY))
   for key in sorted(addrHistory, key=lambda outpoint: outpoint.blkNum):
      print binary_to_hex(key.txHash, BIGENDIAN)[:8]+'...', key.txOutIndex,
      print coin2str(addrHistory[key].totalAccumulated, 4),
      print coin2str(addrHistory[key].balance, 4),
      print "Unspent" if addrHistory[key].txIn == None else "Spent"
      
def addBlockToPrunedTree(prunedTree, blk):
   global totalAccumulated
   global balance
   if blk.blkNum %100000 == 0:
      print blk.blkNum,
   if blk.blkNum %1000000 == 0:
      print
   for tx in blk.txList:
      for txIn in tx.txInList:
         if txIn.outpoint.txHash != BIN_32_BYTE_0:
            spentOutpoint = PyOutPoint()
            spentOutpoint.txHash, spentOutpoint.txOutIndex = txIn.outpoint.txHash, txIn.outpoint.txOutIndex     
            if spentOutpoint.serialize() in prunedTree:
               balance -= prunedTree[spentOutpoint.serialize()].txOut.value 
               del prunedTree[spentOutpoint.serialize()]
      for txOut in tx.txOutList:
         totalAccumulated += txOut.value
         balance += txOut.value
         outpoint = PyOutPoint()
         outpoint.txHash, outpoint.txOutIndex = tx.txHash, txOut.txOutIndex       
         prunedTree[outpoint.serialize()] = TxIOPair(txOut, None, totalAccumulated, balance)

               
def addFileToPrunedTree(prunedTree, blkFileName):
   print blkFileName
   with open(blkFileName, 'rb') as f:
      fSize = getFileSize(f)
      while f.tell() < fSize:
         blk = getNextBlock(f)
         if blk != None:
            addBlockToPrunedTree(prunedTree, blk)
            
def getPrunedTree():
   prunedTree = {}
   for blkFileName in blkFileNameList:
      addFileToPrunedTree(prunedTree, blkFileName)
   return prunedTree  

print "Block Chain Parser HW #4 Exercise #3: "
prunedTree = getPrunedTree()
print
print "Unspent txOuts: ", len(prunedTree.keys())
print "Total unspent bitcoins: ", coin2str(balance, 4), "(" + 50*(blkCounter+1) + ")"
treeSize = 0
for key,value in prunedTree.iteritems():
   treeSize += len(value.txOut.script)+45
print "Tree Size: ", treeSize













