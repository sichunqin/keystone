import os
import patchEnclaveImg

defaultImagePath = "/home/sichunqin/code/github/sichunqin/keystone/build/overlay/root/hello-world/hello-world"

defaultRootKeyFolder = "/home/sichunqin/code/github/sichunqin/keystone/keystone-tools/eapp_root_key"
defaultImageKeyfolder = "/home/sichunqin/code/github/sichunqin/keystone/keystone-tools/eapp_image_key"

def main():
    patchEnclaveImg.patchElfImage(defaultImagePath,
                                 defaultRootKeyFolder,
                                 defaultImageKeyfolder)

if __name__ == "__main__":
    main()
