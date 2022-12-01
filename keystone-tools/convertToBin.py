from elftools.elf.elffile import ELFFile
import os

defaultElfPath = "/home/sichunqin/code/github/sichunqin/keystone/build/overlay/root/eyrie-rt.patch"
def get_args(defaultElfPath
             ):
    from argparse import ArgumentParser

    parser = ArgumentParser()

    parser.add_argument('--in', dest = 'elfPath',
                        default = defaultElfPath,
                        help='Input elf file path, default is' + defaultElfPath)


    parser.add_argument('-v', '--version', action='version',
                        version='%(prog)s 1.0', help='version')

    return parser.parse_args()

def convertToBin():
    args = get_args(defaultElfPath)
    elfPath = args.elfPath
    binPath = elfPath + ".bin"

    with open(elfPath, 'rb') as elffile:
        embedSec = ELFFile(elffile).get_section_by_name(".embed")

        for segment in ELFFile(elffile).iter_segments():
           if(segment.header.p_filesz > 0):

              offset = segment.header.p_offset
              size = segment.header.p_filesz
              embedData = embedSec.data()
              break
    if(size <= 0):
        raise Exception("Elf file doesn't contain any PT_LOAD data")

    with open(elfPath,"r+b") as wf:
        wf.seek(offset)
        raw = wf.read(size)

    if(not segment.section_in_segment(embedSec)):
        zeroBytes = bytes((4096 - size %4096)%4096)
        raw = raw + zeroBytes
        raw = raw + embedData

    if(os.path.exists(binPath)):
        os.remove(binPath)
    with open(binPath,"wb") as wf:
        wf.write(raw)
    print("The output file is generated at " + binPath)
    pass

def main():
    convertToBin()
    pass

if __name__ == "__main__":
    main()

