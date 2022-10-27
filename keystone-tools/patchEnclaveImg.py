import ed25519
from elftools.elf.elffile import ELFFile
import shutil
import os

os.chdir(os.path.dirname(__file__))

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
                        default=os.path.join(defaultRootKeyFolder,'root_enc.key'),
                        help='Enc Root Key Path, default is ' + os.path.join(defaultRootKeyFolder,'root_enc.key'))


    parser.add_argument('--out', dest = 'newImagePath',
                        default = defaultImagePath + ".patched", help='Patched Image Path')

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

def getPatchedData(pubKeyPath,
              prvKeyPath,
              rootPrvKeyPath,
              imagePath,
              encKeyPath,
              rootEncKeyPath):

    magic = b"!emb"
    version = b'\x00'

    publicKey = getContentFromFile(pubKeyPath)
    publicKeySignature = signFile(pubKeyPath,rootPrvKeyPath)

    imageSignatgure = signBinaryInElf(imagePath,prvKeyPath)

    encryptedEncKey = bytes(32)

    return magic + version + publicKey + publicKeySignature + imageSignatgure + encryptedEncKey


def signBinaryInElf(elfPath, prvKeyPath):

    raw = getDataToSignFromElf(elfPath)
    keydata = open(prvKeyPath,"rb").read()
    signing_key = ed25519.SigningKey(keydata)

    sig = signing_key.sign(raw)
    print("Raw: " + raw[:123].hex() + "size: " + str(len(raw)))
    print("Signature: " + sig.hex())
    print("Private key path: " + prvKeyPath)
    return sig

def getContentFromFile(filePath):
    with open(filePath,"r+b") as f:
       data = f.read()
    return data

def signFile(filePath, signKeyPath):
    keydata = open(signKeyPath,"rb").read()
    signing_key = ed25519.SigningKey(keydata)
    msg = open(filePath,"rb").read()
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
    newImagePath = args.newImagePath

    patch = getPatchedData(
        pubKeyPath,
        prvKeyPath,
        rootPrvKeyPath,
        imagePath,
        encKeyPath,
        rootEncKeyPath)

    replaceSection(
        imagePath,
        patch,
        newImagePath)
    print("Start to verfiy patched image file")
    verifyPatchedImage(newImagePath,
                       pubKeyPath,
                       encKeyPath,
                       rootPubKeyPath,
                       rootEncKeyPath)
    print("Succeed to verfiy patched image file.")
    shutil.move(imagePath, imagePath + ".unpatch")
    shutil.copy(newImagePath, imagePath)
    pass

def test():
    defaultImagePath = os.path.join("image","eyrie-rt")
    defaultRootKeyFolder = "rt_root_key"
    defaultImageKeyfolder = "rt_image_key"
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
