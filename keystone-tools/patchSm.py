import ed25519
from elftools.elf.elffile import ELFFile
import shutil
import os

def get_args():
    from argparse import ArgumentParser
    imageDefault = 'eyrie-rt'

    parser = ArgumentParser()

    parser.add_argument('--in', dest = 'imagePath',
                        default = imageDefault, help='input image path')

    parser.add_argument('--rt_pub_key', dest = 'rtPubKeyPath',
                        default= os.path.join('root_key','sign.pub'), help='Public key')

    parser.add_argument('--eapp_pub_key', dest = 'eappPubKeyPath',
                        default= os.path.join('key','sign.pub'), help='Public key')

    parser.add_argument('--rt_enc_key', dest = 'rtEncKeyPath',
                        default=os.path.join('key','enc.key'), help='Enc Key Path')

    parser.add_argument('--eapp_enc_key', dest = 'eappEncKeyPath',
                        default=os.path.join('key','enc.key'), help='Enc Key Path')

    parser.add_argument('--out', dest = 'newImagePath',
                        default = imageDefault + ".patched", help='Patched Image Path')

    parser.add_argument('-v', '--version', action='version',
                        version='%(prog)s 1.0', help='version')

    return parser.parse_args()



#  Patch Data Format:
#  byte magic_number[MAGIC_NUMBER_SIZE];                //!emb ASCII code.
#  byte protocol_version;                               //Current version is 0.
#  byte rt_root_public_key[PUBLIC_KEY_SIZE];
#  byte eapp_root_public_key[PUBLIC_KEY_SIZE];
#  byte rt_root_enc_key[ENC_KEY_SIZE];
#  byte eapp_rt_enc_key[ENC_KEY_SIZE];

def getPatchedData(pubKeyPath,
              prvKeyPath,
              rootSignKeyPath,
              imagePath,
              encKeyPath,
              encRootKeyPath):

    magic = b"!emb"
    version = b'\x00'

    publicKey = getContentFromFile(pubKeyPath)
    publicKeySignature = signFile(pubKeyPath,rootSignKeyPath)

    imageSignatgure = signBinaryInElf(imagePath,prvKeyPath)

    encryptedEncKey = bytes(16)

    return magic + version + publicKey + publicKeySignature + imageSignatgure + encryptedEncKey

#  Need to execute riscv64-unknown-linux-gnu-objcopy -O binary eyrie-rt eyrie-rt.bin to get raw binary, then pad the binary to 4K aligment, then sign it.

def signBinaryInElf(elfPath, prvKeyPath):

    with open(elfPath, 'rb') as elffile:
        for segment in ELFFile(elffile).iter_segments():
           if(segment.header.p_filesz > 0):
              offset = segment.header.p_offset
              size = segment.header.p_filesz

    with open(elfPath,"r+b") as wf:
        wf.seek(offset)
        raw = wf.read(size)

    raw = raw + bytes(4096 - size % 4096)

    keydata = open(prvKeyPath,"rb").read()
    signing_key = ed25519.SigningKey(keydata)

    sig = signing_key.sign(raw)
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


def insertSectionInImage(imagePath,
                          dataPath,
                          newImagePath):
    elffile = ELFFile(open(imagePath, 'rb'))
    section = elffile.get_section_by_name(".embed")
    offset = section.header.sh_offset
    size = section.header.sh_size
    shutil.copyfile(imagePath,newImagePath)
    with open(newImagePath,"r+b") as wf:
        with open(dataPath,"rb") as rf:
            embededData = rf.read()
        embededData = embededData[:size]
        wf.seek(offset)
        wf.write(embededData)

def main():
    args = get_args()

    imagePath = args.imagePath
    pubKeyPath = args.pubKeyPath
    prvKeyPath = args.prvKeyPath
    rootSignKeyPath = args.rootSignKeyPath
    encKeyPath = args.encKeyPath
    encRootKeyPath = args.encRootKeyPath
    newImagePath = args.newImagePath

    patch = getPatchedData(pubKeyPath,prvKeyPath,rootSignKeyPath,imagePath,encKeyPath,encRootKeyPath)

    replaceSection(imagePath, patch, newImagePath)
    return

if __name__ == "__main__":
    main()
