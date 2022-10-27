import os
import patchEnclaveImg

defaultImagePath = "../build/overlay/root/hello-world/hello-world"

defaultRootKeyFolder = "eapp_root_key"
defaultImageKeyfolder = "eapp_image_key"

def main():
    patchEnclaveImg.patchElfImage(defaultImagePath,
                                 defaultRootKeyFolder,
                                 defaultImageKeyfolder)

if __name__ == "__main__":
    main()
