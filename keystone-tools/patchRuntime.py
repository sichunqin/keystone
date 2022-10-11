import os
import patchEnclaveImg

defaultImagePath = os.path.join("image","eyrie-rt")
defaultRootKeyFolder = "rt_root_key"
defaultImageKeyfolder = "rt_image_key"

def main():
    patchEnclaveImg.patchElfImage(defaultImagePath,
                                 defaultRootKeyFolder,
                                 defaultImageKeyfolder)

if __name__ == "__main__":
    main()
