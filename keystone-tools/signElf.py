import ed25519
from elftools.elf.elffile import ELFFile
import shutil
import os
from Crypto.Cipher import AES
from Crypto.Util import Counter
#os.chdir(os.path.dirname(__file__))
defaultImagePath = "/home/sichunqin/code/github/sichunqin/keystone/build/overlay/root/hello-world/hello-world"

defaultRootKeyFolder = "/home/sichunqin/code/github/sichunqin/keystone/keystone-tools/eapp_root_key"
defaultImageKeyfolder = "/home/sichunqin/code/github/sichunqin/keystone/keystone-tools/eapp_image_key"


def get_args(defaultImagePath,
             defaultRootKeyFolder,
             defaultImageKeyfolder):
    from argparse import ArgumentParser

    parser = ArgumentParser()

    parser.add_argument('--in', dest = 'imagePath',
                        default = defaultImagePath,
                        help='Input image path, default is' + defaultImagePath)

    parser.add_argument('--out', dest = 'signedImagePath',
                        default = defaultImagePath + ".signed",
                        help='Output image path, default is' + defaultImagePath + ".signed")

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

    parser.add_argument('--needEnc', action='store_true', help='Need to encrypt image if exist')


    parser.add_argument('--iv', dest = 'iv', type=int,
                        default= 0,
                        help='IV')

    parser.add_argument('-v', '--version', action='version',
                        version='%(prog)s 1.0', help='version')

    return parser.parse_args()

"""
  byte magic_number[MAGIC_NUMBER_SIZE];             //!emb ASCII code.
  byte protocol_version;                             //Current version is 0.
  short header_size;
  byte function_map[2];
  byte public_key[PUBLIC_KEY_SIZE];                  //RT or Eapp public key
  byte image_signature[SIGNATURE_SIZE];              //RT or Eapp image signature.
  byte encrypted_enc_key[ENC_KEY_SIZE];              //RT or Eapp encryption key protected by RT or Eapp root enc key.
  byte iv[16]
  int image_size;                                    //4 bytes
  int text_size;                                     //4 bytes
  byte header_signature[SIGNATURE_SIZE];              //embed data signed by RT or Eapp root private key
"""
def generateHeader(pubKeyPath,
              prvKeyPath,
              rootPrvKeyPath,
              bodyData,
              encKeyPath,
              rootEncKeyPath,
              needImageEnc,
              textSize,
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

    imageSignature = signData(bodyData,prvKeyPath)
    imageSize = len(bodyData)

    text_size = textSize

    key = getContentFromFile(rootEncKeyPath)
    data = getContentFromFile(encKeyPath)
    ctr = Counter.new(128,initial_value = 0)
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)
    encryptedEncKey = aes.encrypt(data)

    headerData = magic + version + embedSize.to_bytes(2,byteorder="little")  +  \
            funcMapInBytes + publicKey + imageSignature + encryptedEncKey + \
            iv + imageSize.to_bytes(4, byteorder="little")  + \
            text_size.to_bytes(4, byteorder="little")

    headerSignature = signData(headerData, rootPrvKeyPath)

    headerData = headerData + headerSignature

    assert(len(headerData) == (embedSize + 64))

    return headerData


def generateFileSignature(elfPath, prvKeyPath):
    raw = getContentFromFile(elfPath)
    #raw,size = getBinaryToSignFromElf(elfPath)

    #keydata = open(prvKeyPath,"rb").read()
    keyData = getContentFromFile(prvKeyPath)
    signing_key = ed25519.SigningKey(keyData)

    sig = signing_key.sign(raw)

    print("Raw: " + raw[:123].hex() + " size: " + str(len(raw)))
    print("Signature: " + sig.hex())
    print("Private key path: " + prvKeyPath)
    return sig, len(raw)


def getElfTextSize(elfPath):
    with open(elfPath, 'rb') as elffile:
        textSec = ELFFile(elffile).get_section_by_name(".text")
        textSize = textSec.data_size

    return textSize

def encryptFile(elfPath, keyPath, counter = 0):
    print("Start to encrypt ELF file. ")

    raw = getContentFromFile(elfPath)

    key = getContentFromFile(keyPath)
    ctr = Counter.new(128,initial_value = counter)
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)
    encRaw = aes.encrypt(raw)

    # verify content is encrypted correctly
    ctrDec = Counter.new(128,initial_value = counter)
    aes = AES.new(key, AES.MODE_CTR, counter=ctrDec)
    decData = aes.decrypt(encRaw)

    assert(raw == decData)

    return encRaw

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

"""
  byte magic_number[MAGIC_NUMBER_SIZE];             //!emb ASCII code.
  byte protocol_version;                             //Current version is 0.
  short header_size;
  byte function_map[2];
  byte public_key[PUBLIC_KEY_SIZE];                  //RT or Eapp public key
  byte image_signature[SIGNATURE_SIZE];              //RT or Eapp image signature.
  byte encrypted_enc_key[ENC_KEY_SIZE];              //RT or Eapp encryption key protected by RT or Eapp root enc key.
  byte iv[16]
  int image_size;                                    //4 bytes
  int text_size;                                     //4 bytes
  byte header_signature[SIGNATURE_SIZE];              //embed dat signed by RT or Eapp root private key
"""
def verifySignedFile(
    imagePath,
    signedImagePath,
    pubKeyPath,
    encKeyPath,
    rootPubKeyPath,
    rootEncKeypath):

    fileContent = getContentFromFile(signedImagePath)
    i=0
    magic = fileContent[i:i+4]
    i+=4

    version = fileContent[i: i+1]
    i+=1

    headerSize = int.from_bytes(fileContent[i: i+2], "little")
    i+=2

    functionMap = int.from_bytes(fileContent[i: i+2],"little")
    i+=2

    needEnc = functionMap & 1

    publicKey = fileContent[i: i+32]
    i+=32

    imageSignature = fileContent[i:i+64]
    i+=64

    encryptedEncKey=fileContent[i:i+32]
    i+=32

    ctr = Counter.new(128,initial_value = 0)
    rootEncKey = getContentFromFile(rootEncKeypath)
    aes = AES.new(rootEncKey, AES.MODE_CTR, counter=ctr)
    encKey = aes.decrypt(encryptedEncKey)
    oriEncKey = getContentFromFile(encKeyPath)
    assert(encKey == oriEncKey)

    iv=fileContent[i:i+16]
    i+=16

    imageSize = int.from_bytes(fileContent[i: i+4], "little")
    i+=4

    textSize = int.from_bytes(fileContent[i: i+4], "little")
    i+=4

    headerSignature = fileContent[i:i+64]
    i+=64
    print("image sig: " + imageSignature.hex())

    if(magic != b"!emb"):
        raise Exception("Magic number is not correct in patched image!")

    originalPublicKey = open(pubKeyPath,"rb").read()

    if(publicKey != originalPublicKey):
        raise Exception("Public key is not correct in patched image!")

    rootPubKey = open(rootPubKeyPath,"rb").read()
    rootVerifyKey = ed25519.VerifyingKey(rootPubKey)
    rootVerifyKey.verify(headerSignature,fileContent[0: headerSize])  # If fail, exception will be raised.

    bodyData = fileContent[i:]
    bodyDataSize = len(bodyData)
    assert(bodyDataSize == imageSize)

    verifyKey = ed25519.VerifyingKey(publicKey)

    verifyKey.verify(imageSignature,bodyData)

    raw = getContentFromFile(imagePath)
    if(needEnc):
        counter = int.from_bytes(iv, 'little')
        ctrDec = Counter.new(128,initial_value = counter)
        key = getContentFromFile(encKeyPath)
        aes = AES.new(key, AES.MODE_CTR, counter=ctrDec)
        decData = aes.decrypt(bodyData)
        assert(raw == decData)

def signElf(defaultImagePath,
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
    signedImagePath = args.signedImagePath
    iv = args.iv

    if(needEnc):
        bodyData = encryptFile(imagePath,encKeyPath)
    else:
        bodyData = getContentFromFile(imagePath)

    textSize = getElfTextSize(imagePath)

    header = generateHeader(
        pubKeyPath,
        prvKeyPath,
        rootPrvKeyPath,
        bodyData,
        encKeyPath,
        rootEncKeyPath,
        needEnc,
        textSize,
        iv)

    with open(signedImagePath,"wb") as wf:
        wf.write(header + bodyData)

    print("Start to verify signed file")
    verifySignedFile(
                       imagePath,
                       signedImagePath,
                       pubKeyPath,
                       encKeyPath,
                       rootPubKeyPath,
                       rootEncKeyPath)
    print("Succeed to verify signed image file.")
    print("The signed file is stoared at " + signedImagePath)

    pass

def test():

    defaultImagePath = "/home/sichunqin/code/github/sichunqin/keystone/build/overlay/root/eyrie-rt"
    defaultRootKeyFolder = "/home/sichunqin/code/github/sichunqin/keystone/keystone-tools/rt_root_key"
    defaultImageKeyfolder = "/home/sichunqin/code/github/sichunqin/keystone/keystone-tools/rt_image_key"

    signElf(defaultImagePath,
                  defaultRootKeyFolder,
                  defaultImageKeyfolder
                  )
    pass

def main():

    defaultImagePath = "/home/sichunqin/code/github/sichunqin/keystone/build/overlay/root/examples/hello/hello"
    defaultRootKeyFolder = "/home/sichunqin/code/github/sichunqin/keystone/keystone-tools/eapp_root_key"
    defaultImageKeyfolder = "/home/sichunqin/code/github/sichunqin/keystone/keystone-tools/eapp_image_key"
    signElf(defaultImagePath,
                  defaultRootKeyFolder,
                  defaultImageKeyfolder
                  )

    return

if __name__ == "__main__":
    main()
