import os
import patchEnclaveImg

defaultImagePath = os.path.join("image","hello-world")
defaultRootKeyFolder = "eapp_root_key"
defaultImageKeyfolder = "eapp_image_key"

def main():
    patchEnclaveImg.patchElfImage(defaultImagePath,
                                 defaultRootKeyFolder,
                                 defaultImageKeyfolder)

if __name__ == "__main__":
    main()
