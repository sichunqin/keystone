import os
import patchEnclaveImg

defaultImagePath = "/home/sichunqin/code/github/sichunqin/keystone/build/overlay/root/eyrie-rt"
defaultRootKeyFolder = "/home/sichunqin/code/github/sichunqin/keystone/keystone-tools/rt_root_key"
defaultImageKeyfolder = "/home/sichunqin/code/github/sichunqin/keystone/keystone-tools/rt_image_key"

def main():
    patchEnclaveImg.patchElfImage(defaultImagePath,
                                 defaultRootKeyFolder,
                                 defaultImageKeyfolder)

if __name__ == "__main__":
    main()
