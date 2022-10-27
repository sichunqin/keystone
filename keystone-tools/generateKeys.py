import ed25519
import os

def get_args():
    from argparse import ArgumentParser

    parser = ArgumentParser()

    parser.add_argument('--name', type=str,
                        default="key", help='Generated key file name, default is key')

    parser.add_argument('--out', dest='outFolder', type=str,
                        default='key', help='output key file folder, defaut is key')

    parser.add_argument('-v', '--version', action='version',
                        version='%(prog)s 1.0', help='version')

    return parser.parse_args()
def genSignKeyPair(prvKeyPath, pubKeyPath):

    privKey, pubKey = ed25519.create_keypair()

    with open(prvKeyPath,"wb") as wf:
        wf.write(privKey.to_bytes())

    with open(pubKeyPath,"wb") as w:
        w.write(pubKey.to_bytes())


def genEncKey(encKeyPath):

    key = os.urandom(32)

    with open(encKeyPath,"wb") as wf:
        wf.write(key)

def main():
    args = get_args()
    outFolder =args.outFolder
    fileName = args.name

    os.makedirs(outFolder, exist_ok=True)

    prvPath = os.path.join(outFolder, fileName + '.prv')
    pubPath = os.path.join(outFolder, fileName + '.pub')
    encPath = os.path.join(outFolder, fileName + '.enc')

    genSignKeyPair(prvPath, pubPath)
    genEncKey(encPath)

if __name__ == "__main__":
    main()