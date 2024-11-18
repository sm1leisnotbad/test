from Crypto.Cipher import AES
from Crypto.Hash import MD5

class Config:
    def __init__(self):
        self.szArgFlag = b'\x00' * 8
        self.rgbArgFlagValueMD5 = b'\x00' * 16
        self.rgbTargetMac = b'\x00' * 6
        self.wszTargetComputerName = b'\x00' * 32 * 2
        self.fDoCheckIsSystem = b'\x00' * 4
        self.wszEncryptedFilePath = b'\x00' * 260 * 2
        self.dwDatFileOffsetToEncDll = b'\x00' * 4
        self.dwEncryptedFileSize = b'\x00' * 4
        self.rgbAESKeyForDatFile = b'\x00' * 16
        self.rgbIVForDatFile = b'\x00' * 16
        self.rgbMD5HashDatFile = b'\x00' * 16
        self.dwFlagDeletedDatFile = b'\x00' * 4
        self.fShouldUnloadStealthVector = b'\x00' * 8
        self.fShouldTerminateProcess = b'\x00' * 4

    def input_data(self):
        # Collect data for each field with validation checks
        szArgFlag_input = input("Enter szArgFlag (8 characters): ")
        if len(szArgFlag_input) != 8:
            raise ValueError("szArgFlag must be exactly 8 characters long.")
        self.szArgFlag = szArgFlag_input.encode('utf-8')

        rgbArgFlagValueMD5 = bytes.fromhex(input("Enter rgbArgFlagValueMD5 (16 bytes in hex): "))
        if len(bytes.fromhex(rgbArgFlagValueMD5)) != 16:
            raise ValueError("rgbTargetMac must be exactly 16 bytes in hex.")
        self.rgbArgFlagValueMD5 = bytes.fromhex(rgbArgFlagValueMD5)

        rgbTargetMac_input = input("Enter rgbTargetMac (6 bytes in hex): ")
        if len(bytes.fromhex(rgbTargetMac_input)) != 6:
            raise ValueError("rgbTargetMac must be exactly 6 bytes in hex.")
        self.rgbTargetMac = bytes.fromhex(rgbTargetMac_input)

        wszTargetComputerName_input = input("Enter wszTargetComputerName (32 characters): ")
        if len(wszTargetComputerName_input) > 32:
            raise ValueError("wszTargetComputerName must not exceed 32 characters.")
        wszTargetComputerName_input = wszTargetComputerName_input.ljust(32, '\x00')
        self.wszTargetComputerName = wszTargetComputerName_input.encode('utf-16le')

        fDoCheckIsSystem = int(input("Enter fDoCheckIsSystem (integer): "))
        if fDoCheckIsSystem not in (0, 1):
            raise ValueError("fDoCheckIsSystem must be 0 or 1.")
        # change fDoCheckIsSystem to bytes
        self.fDoCheckIsSystem = fDoCheckIsSystem.to_bytes(4, byteorder='little')

        wszEncryptedFilePath_input = input("Enter wszEncryptedFilePath (260 characters): ")
        if len(wszEncryptedFilePath_input) > 260:
            raise ValueError("wszEncryptedFilePath must not exceed 260 characters.")
        wszEncryptedFilePath_input = wszEncryptedFilePath_input.ljust(260, '\x00')    
        self.wszEncryptedFilePath = wszEncryptedFilePath_input.encode('utf-16le')

        dwDatFileOffsetToEncDll = int(input("Enter dwDatFileOffsetToEncDll (integer): "))
        if dwDatFileOffsetToEncDll < 0:
            raise ValueError("dwDatFileOffsetToEncDll must be a non-negative integer.")
        self.dwDatFileOffsetToEncDll = dwDatFileOffsetToEncDll.to_bytes(4, byteorder='little')

        dwEncryptedFileSize = int(input("Enter dwEncryptedFileSize (integer): "))
        if dwEncryptedFileSize < 0:
            raise ValueError("dwEncryptedFileSize must be a non-negative integer.")
        self.dwEncryptedFileSize = dwEncryptedFileSize.to_bytes(4, byteorder='little')

        rgbAESKeyForDatFile_input = input("Enter rgbAESKeyForDatFile (16 bytes in hex): ")
        if len(bytes.fromhex(rgbAESKeyForDatFile_input)) != 16:
            raise ValueError("rgbAESKeyForDatFile must be exactly 16 bytes in hex.")
        self.rgbAESKeyForDatFile = bytes.fromhex(rgbAESKeyForDatFile_input)

        rgbIVForDatFile_input = input("Enter rgbIVForDatFile (16 bytes in hex): ")
        if len(bytes.fromhex(rgbIVForDatFile_input)) != 16:
            raise ValueError("rgbIVForDatFile must be exactly 16 bytes in hex.")
        self.rgbIVForDatFile = bytes.fromhex(rgbIVForDatFile_input)

        self.rgbMD5HashDatFile = bytes.fromhex(input("Enter rgbMD5HashDatFile (16 bytes in hex): "))

        dwFlagDeletedDatFile = int(input("Enter dwFlagDeletedDatFile (integer): "))
        if dwFlagDeletedDatFile not in (0, 1):
            raise ValueError("dwFlagDeletedDatFile must be 0 or 1.")
        self.dwFlagDeletedDatFile = dwFlagDeletedDatFile.to_bytes(4, byteorder='little')

        fShouldUnloadStealthVector = int(input("Enter fShouldUnloadStealthVector (integer, QWORD): "))
        if fShouldUnloadStealthVector < 0:
            raise ValueError("fShouldUnloadStealthVector must be a non-negative integer.")
        self.fShouldUnloadStealthVector = fShouldUnloadStealthVector.to_bytes(8, byteorder='little')

        fShouldTerminateProcess = int(input("Enter fShouldTerminateProcess (integer): "))
        if fShouldTerminateProcess not in (0, 1):
            raise ValueError("fShouldTerminateProcess must be 0 or 1.")
        self.fShouldTerminateProcess = fShouldTerminateProcess.to_bytes(4, byteorder='little')

    def display_data(self):
        print("\nConfig Data:")
        print(f"szArgFlag: {self.szArgFlag}")
        print(f"rgbArgFlagValueMD5: {self.rgbArgFlagValueMD5.hex()}")
        print(f"rgbTargetMac: {self.rgbTargetMac}")
        print(f"wszTargetComputerName: {self.wszTargetComputerName}")
        print(f"fDoCheckIsSystem: {self.fDoCheckIsSystem}")
        print(f"wszEncryptedFilePath: {self.wszEncryptedFilePath}")
        print(f"dwDatFileOffsetToEncDll: {self.dwDatFileOffsetToEncDll}")
        print(f"dwEncryptedFileSize: {self.dwEncryptedFileSize}")
        print(f"rgbAESKeyForDatFile: {self.rgbAESKeyForDatFile.hex()}")
        print(f"rgbIVForDatFile: {self.rgbIVForDatFile.hex()}")
        print(f"rgbMD5HashDatFile: {self.rgbMD5HashDatFile.hex()}")
        print(f"dwFlagDeletedDatFile: {self.dwFlagDeletedDatFile}")
        print(f"fShouldUnloadStealthVector: {self.fShouldUnloadStealthVector}")
        print(f"fShouldTerminateProcess: {self.fShouldTerminateProcess}")
    def to_string(self):
        data_str = self.szArgFlag + self.rgbArgFlagValueMD5 + self.rgbTargetMac + self.wszTargetComputerName  + \
                self.fDoCheckIsSystem + self.wszEncryptedFilePath + self.dwDatFileOffsetToEncDll + \
                self.dwEncryptedFileSize + self.rgbAESKeyForDatFile + self.rgbIVForDatFile + self.rgbMD5HashDatFile + \
                self.dwFlagDeletedDatFile + self.fShouldUnloadStealthVector + self.fShouldTerminateProcess
        return data_str

def encrypt_data(data_str, key, iv):
    cipher = AES.new(key, AES.MODE_CFB, iv)
    ct_bytes = cipher.encrypt(data_str)
    return ct_bytes

# print("Enter key for encrypting config data (16 bytes in hex): ")
# key = bytes.fromhex(input())
# if len(key) != 16:
#     raise ValueError("Key must be exactly 16 bytes long.")
# print("Enter IV for encrypting config data (16 bytes in hex): ")
# iv = bytes.fromhex(input())
# if len(iv) != 16:
#     raise ValueError("IV must be exactly 16 bytes long.")


def bytes_to_cpp_array(data):
    hex_representation = ', '.join(f'0x{byte:02X}' for byte in data)
    return f"unsigned char rgbEncryptedBuffer[] = {{\n  {hex_representation}\n}};"
 
config = Config()
# config.input_data()
# config.display_data()
cpp_array = bytes_to_cpp_array(config.to_string())

import re

# Path to your C++ file
file_path = "test.cpp"

# Read the contents of the file
with open(file_path, "r") as file:
    file_contents = file.read()

# Use a regular expression to find and replace the rgbEncryptedBuffer definition
new_file_contents = re.sub(
    r"unsigned char rgbEncryptedBuffer\[\] = \{.*?\};",
    cpp_array,
    file_contents,
    flags=re.DOTALL
)

# Write the updated content back to the file
with open(file_path, "w") as file:
    file.write(new_file_contents)
