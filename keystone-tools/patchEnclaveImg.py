import ed25519
from elftools.elf.elffile import ELFFile
import shutil
import os
from Crypto.Cipher import AES
from Crypto.Util import Counter
#os.chdir(os.path.dirname(__file__))

def get_args(defaultImagePath,
             defaultRootKeyFolder,
             defaultImageKeyfolder):
    from argparse import ArgumentParser

    parser = ArgumentParser()

    parser.add_argument('--in', dest = 'imagePath',
                        default = defaultImagePath,
                        help='input image path, default is' + defaultImagePath)

    parser.add_argument('--pub_key', dest = 'pubKeyPath',
                        default= os.path.join(defaultImageKeyfolder,'key.pub'),
                        help='Image Public key path, default is ' + os.path.join(defaultImageKeyfolder,'key.pub') )

    parser.add_argument('--prv_key', dest = 'prvKeyPath',
                        default=os.path.join(defaultImageKeyfolder,'key.prv'),
                        help='Image private key path, default is ' + os.path.join(defaultImageKeyfolder,'key.prv'))

    parser.add_argument('--root_prv_key', dest = 'rootPrvKeyPath',
                        default=os.path.join(defaultRootKeyFolder,'root_key.prv'),
                        help='Root Private Key Path, default is ' + os.path.join(defaultRootKeyFolder,'root_key.prv'))

    parser.add_argument('--root_public_key', dest = 'rootPubKeyPath',
                        default=os.path.join(defaultRootKeyFolder,'root_key.pub'),
                        help='Root Public Key Path, default is ' + os.path.join(defaultRootKeyFolder,'root_key.pub'))

    parser.add_argument('--enc_key', dest = 'encKeyPath',
                        default=os.path.join(defaultImageKeyfolder,'key.enc'),
                        help='Image Enc Key Path, default is ' + os.path.join(defaultImageKeyfolder,'key.enc'))

    parser.add_argument('--enc_root_ey', dest = 'rootEncKeyPath',
                        default=os.path.join(defaultRootKeyFolder,'root_key.enc'),
                        help='Enc Root Key Path, default is ' + os.path.join(defaultRootKeyFolder,'root_enc.key'))

    parser.add_argument('--enc', dest = 'needEnc', type=bool,
                        default= False,
                        help='Need to encrypt image')

    parser.add_argument('--iv', dest = 'iv', type=int,
                        default= 0,
                        help='Need to encrypt image')

    parser.add_argument('-v', '--version', action='version',
                        version='%(prog)s 1.0', help='version')

    return parser.parse_args()


#  Patch Data Format:
#  byte magic_number[MAGIC_NUMBER_SIZE];                //!emb ASCII code. 4 bytes
#  byte protocol_version;                               //Current version is 0. 1 byte
#  byte public_key[PUBLIC_KEY_SIZE];                    //RT or Eapp public key 32 bytes
#  byte public_key_signature[SIGNATURE_SIZE];           //The RT or Eapp public key signed by RT or Eapp root private key  64 bytes
#  byte image_signature[SIGNATURE_SIZE];                //RT or Eapp image signature. 64 bytes
#  byte encrypted_enc_key[ENC_KEY_SIZE]                 //Encrypted enc key. 16 byes

"""
  byte magic_number[MAGIC_NUMBER_SIZE];             //!emb ASCII code.
  byte protocol_version;                             //Current version is 0.
  short embed_size;
  byte function_map[2];
  byte public_key[PUBLIC_KEY_SIZE];                  //RT or Eapp public key
  byte image_signature[SIGNATURE_SIZE];              //RT or Eapp image signature.
  byte encrypted_enc_key[ENC_KEY_SIZE];              //RT or Eapp encryption key protected by RT or Eapp root enc key.
  byte iv[16]
  int image_size;                                    //4 bytes
  int text_size;                                     //4 bytes
  byte embed_signature[SIGNATURE_SIZE];              //embed data signed by RT or Eapp root private key
"""
def getPatchedData(pubKeyPath,
              prvKeyPath,
              rootPrvKeyPath,
              imagePath,
              encKeyPath,
              rootEncKeyPath,
              needImageEnc,
              counter = 0
             ):

    magic = b"!emb"
    version = b'\x00'
    embedSize = 4 + 1 + 2 + 2 + 32 + 64 +32 + 16 + 4 + 4
    functionMap = 0

    if(needImageEnc):
        functionMap  = functionMap | 0x1
        pass

    funcMapInBytes = functionMap.to_bytes(2, byteorder="little")

    publicKey = getContentFromFile(pubKeyPath)

    iv = counter.to_bytes(16, byteorder="little")

    imageSignature, imageSize = signBinaryInElf(imagePath,prvKeyPath)

    text_size = getElfTextSize(imagePath)

    key = getContentFromFile(rootEncKeyPath)
    data = getContentFromFile(encKeyPath)
    ctr = Counter.new(128,initial_value = 0)
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)
    encryptedEncKey = aes.encrypt(data)

    patchData = magic + version + embedSize.to_bytes(2,byteorder="little")  +  \
            funcMapInBytes + publicKey + imageSignature + encryptedEncKey + \
            iv + imageSize.to_bytes(4, byteorder="little")  + \
            text_size.to_bytes(4, byteorder="little")

    embedSignature = signData(patchData, rootPrvKeyPath)

    patchData = patchData + embedSignature

    assert(len(patchData) == (embedSize + 64))
    return patchData

def signBinaryInElf(elfPath, prvKeyPath):

    raw,size = getBinaryToSignFromElf(elfPath)

    keydata = open(prvKeyPath,"rb").read()
    signing_key = ed25519.SigningKey(keydata)

    sig = signing_key.sign(raw)
    print("Raw: " + raw[:123].hex() + "size: " + str(len(raw)))
    print("Signature: " + sig.hex())
    print("Private key path: " + prvKeyPath)
    return sig, len(raw)

def getElfTextSize(elfPath):
    with open(elfPath, 'rb') as elffile:
        textSec = ELFFile(elffile).get_section_by_name(".text")
        textSize = textSec.data_size

    return textSize

def encryptBinaryInElf(elfPath, keyPath, counter = 0):

    with open(elfPath, 'rb') as elffile:
        embedSec = ELFFile(elffile).get_section_by_name(".embed")
        embedSize = embedSec.data_size
        for segment in ELFFile(elffile).iter_segments():
           if(segment.header.p_filesz > 0):

              offset = segment.header.p_offset
              size = segment.header.p_filesz
              break
    if(segment.section_in_segment(embedSec)):
        size = size - embedSize
    if(size <= 0):
        raise Exception("Elf file doesn't contain any PT_LOAD data")

    with open(elfPath,"r+b") as wf:
        wf.seek(offset)
        raw = wf.read(size)

    key = getContentFromFile(keyPath)
    ctr = Counter.new(128,initial_value = counter)
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)
    encRaw = aes.encrypt(raw)

    tempElfPath = elfPath + ".temp"
    shutil.copyfile(elfPath,tempElfPath)

    with open(tempElfPath,"r+b") as wf:
        wf.seek(offset)
        wf.write(encRaw)

    # verify data is encrypted correctly
    print("Start to verify image is encrypted properly")

    with open(tempElfPath,"rb") as wf:
        wf.seek(offset)
        encData = wf.read(size)

    ctrDec = Counter.new(128,initial_value = counter)
    aes = AES.new(key, AES.MODE_CTR, counter=ctrDec)
    decData = aes.decrypt(encData)

    assert(raw == decData)
    shutil.copyfile(tempElfPath,elfPath)
    os.remove(tempElfPath)
    print("Alreadly verify image is encrypted correctly")

def getContentFromFile(filePath):
    with open(filePath,"r+b") as f:
       data = f.read()
    return data

def signFile(filePath, signKeyPath):

    msg = open(filePath,"rb").read()
    return signData(msg, signKeyPath)

def signData(msg, signKeyPath):
    keyData = open(signKeyPath,"rb").read()
    signing_key = ed25519.SigningKey(keyData)
    sig = signing_key.sign(msg)
    return sig

def replaceSection(imagePath,
                   embededData,
                   newImagePath):
    elffile = ELFFile(open(imagePath, 'rb'))
    section = elffile.get_section_by_name(".embed")
    offset = section.header.sh_offset
    size = section.header.sh_size
    shutil.copyfile(imagePath,newImagePath)

    with open(newImagePath,"r+b") as wf:

        wf.seek(offset)
        wf.write(embededData)
    print("Successfully patch. patched file is " + imagePath)

def getDataToSignFromElf(elfPath):
    with open(elfPath, 'rb') as elffile:
        embedSec = ELFFile(elffile).get_section_by_name(".embed")
        embedSize = embedSec.data_size
        for segment in ELFFile(elffile).iter_segments():
           if(segment.header.p_filesz > 0):

              offset = segment.header.p_offset
              size = segment.header.p_filesz
              break
    if(segment.section_in_segment(embedSec)):
        size = size - embedSize
    if(size <= 0):
        raise Exception("Elf file doesn't contain any PT_LOAD data")

    with open(elfPath,"r+b") as wf:
        wf.seek(offset)
        raw = wf.read(size)
    if(size % 4096 > 0 ):
        raw = raw + bytes(4096 - size % 4096)
    print("Data to sign len is " + str(len(raw)) )
    return raw

def getBinaryToSignFromElf(elfPath):
    with open(elfPath, 'rb') as elffile:
        embedSec = ELFFile(elffile).get_section_by_name(".embed")
        embedSize = embedSec.data_size
        for segment in ELFFile(elffile).iter_segments():
           if(segment.header.p_filesz > 0):

              offset = segment.header.p_offset
              size = segment.header.p_filesz
              break
    if(segment.section_in_segment(embedSec)):
        size = size - embedSize
    if(size <= 0):
        raise Exception("Elf file doesn't contain any PT_LOAD data")

    with open(elfPath,"r+b") as wf:
        wf.seek(offset)
        raw = wf.read(size)
    print("Data to sign len is " + str(len(raw)) )
    return raw, size


#  Patch Data Format:
#  byte magic_number[MAGIC_NUMBER_SIZE];                //!emb ASCII code. 4 bytes
#  byte protocol_version;                               //Current version is 0. 1 byte
#  byte public_key[PUBLIC_KEY_SIZE];                    //RT or Eapp public key 32 bytes
#  byte public_key_signature[SIGNATURE_SIZE];           //The RT or Eapp public key signed by RT or Eapp root private key  64 bytes
#  byte image_signature[SIGNATURE_SIZE];                //RT or Eapp image signature. 64 bytes
#  byte encrypted_enc_key[ENC_KEY_SIZE]                 //Encrypted Enc key. 32 bytes

def verifyPatchedImage(
    newImagePath,
    pubKeyPath,
    encKeyPath,
    rootPubKeyPath,
    rootEncKeypath):

    elffile = ELFFile(open(newImagePath, 'rb'))
    section = elffile.get_section_by_name(".embed").data()

    i=0
    magic = section[i:i+4]
    i+=4
    version = section[i: i+1]
    i+=1
    publicKey = section[i: i+32]
    i+=32
    publicKeySignature = section[i:i+64]
    i+=64
    imageSignature = section[i:i+64]
    i+=64
    encryptedEncKey=section[i:i+32]

    if(magic != b"!emb"):
        raise Exception("Magic number is not correct in patched image!")

    originalPublicKey = open(pubKeyPath,"rb").read()

    if(publicKey != originalPublicKey):
        raise Exception("Public key is not correct in patched image!")

    rootPubKey = open(rootPubKeyPath,"rb").read()
    rootVerifyKey = ed25519.VerifyingKey(rootPubKey)
    rootVerifyKey.verify(publicKeySignature,publicKey)  # If fail, exception will be raised.

    raw = getDataToSignFromElf(newImagePath)

    verifyKey = ed25519.VerifyingKey(publicKey)

    verifyKey.verify(imageSignature,raw)

    pass

"""
  byte magic_number[MAGIC_NUMBER_SIZE];             //!emb ASCII code.
  byte protocol_version;                             //Current version is 0.
  short embed_size;
  byte function_map[2];
  byte public_key[PUBLIC_KEY_SIZE];                  //RT or Eapp public key
  byte image_signature[SIGNATURE_SIZE];              //RT or Eapp image signature.
  byte encrypted_enc_key[ENC_KEY_SIZE];              //RT or Eapp encryption key protected by RT or Eapp root enc key.
  byte iv[16]
  int image_size;                                    //4 bytes
  int text_size;                                     //4 bytes
  byte embed_signature[SIGNATURE_SIZE];              //embed dat signed by RT or Eapp root private key
"""
def verifyPatch(
    newImagePath,
    pubKeyPath,
    encKeyPath,
    rootPubKeyPath,
    rootEncKeypath):

    elffile = ELFFile(open(newImagePath, 'rb'))
    section = elffile.get_section_by_name(".embed").data()

    i=0
    magic = section[i:i+4]
    i+=4

    version = section[i: i+1]
    i+=1

    embedSize = int.from_bytes(section[i: i+2], "little")
    i+=2

    functionMap = int.from_bytes(section[i: i+2],"little")
    i+=2

    needEnc = functionMap & 1

    publicKey = section[i: i+32]
    i+=32

    imageSignature = section[i:i+64]
    i+=64

    encryptedEncKey=section[i:i+32]
    i+=32

    iv=section[i:i+16]
    i+=16

    imageSize = int.from_bytes(section[i: i+4], "little")
    i+=4

    textSize = int.from_bytes(section[i: i+4], "little")
    i+=4

    embedSignature = section[i:i+64]
    i+=64
    print("image sig: " + imageSignature.hex())

    if(magic != b"!emb"):
        raise Exception("Magic number is not correct in patched image!")

    originalPublicKey = open(pubKeyPath,"rb").read()

    if(publicKey != originalPublicKey):
        raise Exception("Public key is not correct in patched image!")

    rootPubKey = open(rootPubKeyPath,"rb").read()
    rootVerifyKey = ed25519.VerifyingKey(rootPubKey)
    rootVerifyKey.verify(embedSignature,section[0: embedSize])  # If fail, exception will be raised.

    raw,size = getBinaryToSignFromElf(newImagePath)
    assert(size == imageSize)

    verifyKey = ed25519.VerifyingKey(publicKey)

    verifyKey.verify(imageSignature,raw)
    print("image sig: " + imageSignature.hex())
    print("public key:" + publicKey.hex())

    pass


def patchElfImage(defaultImagePath,
                  defaultRootKeyFolder,
                  defaultImageKeyfolder
                  ):
    args = get_args(defaultImagePath,
                  defaultRootKeyFolder,
                  defaultImageKeyfolder
                  )
    imagePath = args.imagePath
    pubKeyPath = args.pubKeyPath
    prvKeyPath = args.prvKeyPath
    rootPrvKeyPath = args.rootPrvKeyPath
    rootPubKeyPath = args.rootPubKeyPath
    encKeyPath = args.encKeyPath
    rootEncKeyPath = args.rootEncKeyPath
    needEnc = args.needEnc
    iv = args.iv

    newImagePath = args.imagePath + ".patch"

    if(needEnc):
        encryptBinaryInElf(imagePath,encKeyPath)
    patch = getPatchedData(
        pubKeyPath,
        prvKeyPath,
        rootPrvKeyPath,
        imagePath,
        encKeyPath,
        rootEncKeyPath,
        needEnc,
        iv)

    replaceSection(
        imagePath,
        patch,
        newImagePath)
    print("Start to verify patched image file")
    verifyPatch(newImagePath,
                       pubKeyPath,
                       encKeyPath,
                       rootPubKeyPath,
                       rootEncKeyPath)
    print("Succeed to verify patched image file.")
    #shutil.move(imagePath, imagePath + ".unpatch")
    shutil.copy(newImagePath, imagePath)
    #os.remove(newImagePath)
    pass

def test():

    defaultImagePath = "/home/sichunqin/code/github/sichunqin/keystone/build/overlay/root/eyrie-rt"
    defaultRootKeyFolder = "/home/sichunqin/code/github/sichunqin/keystone/keystone-tools/rt_root_key"
    defaultImageKeyfolder = "/home/sichunqin/code/github/sichunqin/keystone/keystone-tools/rt_image_key"

    patchElfImage(defaultImagePath,
                  defaultRootKeyFolder,
                  defaultImageKeyfolder
                  )
    pass

def testSig():
    prvKeyPath = "rt_image_key/key.prv"
    pubKeyPath = "rt_image_key/key.pub"
    pub_key = open(pubKeyPath,"rb").read()
    prv_key = open(prvKeyPath,"rb").read()

    #msg = bytes.fromhex("48656C6C6F2C20776F726C6421")

    elfPath = "image/eyrie-rt"
    newElfPath = "image/eyrie-rt.patched"
    msg = getDataToSignFromElf(elfPath)
    signing_key = ed25519.SigningKey(prv_key)

    sig = signing_key.sign(msg)
    verify_key = ed25519.VerifyingKey(pub_key)
    raw = getDataToSignFromElf(newElfPath)
    verify_key.verify(sig,raw)

    pass

def main():
    test()

    return

if __name__ == "__main__":
    main()
