import ed25519
from elftools.elf.elffile import ELFFile
import shutil
import os

os.chdir(os.path.dirname(__file__))

def get_args():
    from argparse import ArgumentParser
    imageDefault = 'image/fw_payload.elf'

    parser = ArgumentParser()

    parser.add_argument('--in', dest = 'imagePath',
                        default = imageDefault, help='input image path, default is ' + imageDefault)

    parser.add_argument('--rt_root_pub_key', dest = 'rtRootPubKeyPath',
                        default= os.path.join('rt_root_key','root_key.pub'),
                        help='Runtime root public key path, default is ' + os.path.join('rt_root_key','root_key.pub'))

    parser.add_argument('--eapp_root_pub_key', dest = 'eappRootPubKeyPath',
                        default= os.path.join('eapp_root_key','root_key.pub'),
                        help='Eapp root public key path, default is ' + os.path.join('eapp_root_key','root_key.pub'))

    parser.add_argument('--rt_root_enc_key', dest = 'rtRootEncKeyPath',
                        default=os.path.join('rt_root_key','root_key.enc'),
                        help='Runtime root enc key path, default is ' + os.path.join('rt_root_key','root_key.enc'))

    parser.add_argument('--eapp_root_enc_key', dest = 'eappRootEncKeyPath',
                        default=os.path.join('eapp_root_key','root_key.enc'),
                        help='Eapp root enc key path, default is ' + os.path.join('eapp_root_key','root_key.enc'))

    parser.add_argument('--out', dest = 'newImagePath',
                        default = imageDefault + ".patched",
                        help='Patched image path')

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

def getPatchedData(
              rtRootPubKeyPath,
              eappRootPubKeyPath,
              rtRootEncKeyPath,
              eappRootEncKeyPath,
              ):

    magic = b"!emb"
    version = b'\x00'

    rtRootPubKey = getContentFromFile(rtRootPubKeyPath)
    eappRootPubKey = getContentFromFile(eappRootPubKeyPath)
    rtRootEncKey = getContentFromFile(rtRootEncKeyPath)
    eappRootEncKey = getContentFromFile(eappRootEncKeyPath)

    return magic + version + rtRootPubKey + eappRootPubKey + rtRootEncKey + eappRootEncKey

def getContentFromFile(filePath):
    with open(filePath,"r+b") as f:
       data = f.read()
    return data

def replaceSection(imagePath,
                   embededData,
                   newImagePath):
    elffile = ELFFile(open(imagePath, 'rb'))
    section = elffile.get_section_by_name(".embed")
    offset = section.header.sh_offset
    size = section.header.sh_size
    shutil.copyfile(imagePath,newImagePath)
    # embededData size shall be equal or less than size.
    if (size < len(embededData)):
        raise Exception("Embeded data size is greaten than .embed section size, which is not allowed")

    with open(newImagePath,"r+b") as wf:
        wf.seek(offset)
        wf.write(embededData)

    print("Successfully patch. patched file is " + newImagePath)

# Verify patched image is patched correctly
def verifyPatch(newImagePath,
              rtRootPubKeyPath,
              eappRootPubKeyPath,
              rtRootEncKeyPath,
              eappRootEncKeyPath):
    print("Start to verify patched image.")
    elffile = ELFFile(open(newImagePath, 'rb'))
    section = elffile.get_section_by_name(".embed").data()

    i=0
    magic = section[i:i+4]
    i+=4

    version = section[i: i+1]
    i+=1

    rtRootPubKey = section[i: i+32]
    i+=32

    eappRootPubKey = section[i:i+32]
    i+=32

    rtRootEncKey = section[i:i+16]
    i+=16

    eappRootEncKey=section[i:i+16]

    if(magic != b"!emb"):
        raise Exception("Magic number is not correct in patched image!")

    o_rtRootPubKey = open(rtRootPubKeyPath,"rb").read()
    o_eappRootPubKey = open(eappRootPubKeyPath,"rb").read()
    o_rtRootEncKey = open(rtRootEncKeyPath,"rb").read()
    o_eappRootEncKey = open(eappRootEncKeyPath,"rb").read()

    if(o_rtRootPubKey != rtRootPubKey or
       o_eappRootPubKey != eappRootPubKey or
       o_rtRootEncKey != rtRootEncKey or
       o_eappRootEncKey != eappRootEncKey):
       raise Exception("Magic number is not correct in patched image!")
    print("Suceed to verify patched image.")
    pass

def patchSm():
    args = get_args()

    patch = getPatchedData(
              args.rtRootPubKeyPath,
              args.eappRootPubKeyPath,
              args.rtRootEncKeyPath,
              args.eappRootEncKeyPath,
              )

    replaceSection(
        args.imagePath,
        patch,
        args.newImagePath)


    verifyPatch(
        args.newImagePath,
        args.rtRootPubKeyPath,
        args.eappRootPubKeyPath,
        args.rtRootEncKeyPath,
        args.eappRootEncKeyPath
    )
    pass

def main():
    patchSm()
    return

if __name__ == "__main__":
    main()

