
from Crypto.Cipher import AES
from Crypto.Hash import CMAC

def f4(u, v, x, z):
    msg = u + v + z
    cobj = CMAC.new(x, ciphermod=AES)
    cobj.update(msg)
    return cobj.digest()

def f5(w, n1, n2, a1, a2):
    salt = b'\x6C\x88\x83\x91\xAA\xF5\xA5\x38\x60\x37\x0B\xDB\x5A\x60\x83\xBE'
    keyid = b'\x62\x74\x6c\x65'
    cobj = CMAC.new(salt, ciphermod=AES)
    cobj.update(w)
    T = cobj.digest()
    le = b'\x01\x00'  # 256
    
    # Ensure A1 and A2 are 56 bits (7 bytes), padding as needed
    a1_padded = a1.rjust(7, b'\x00')
    a2_padded = a2.rjust(7, b'\x00')

    # Compute Mac Key (counter = 0)
    counter_0 = b'\x00'  # Counter = 0
    message_0 = counter_0 + keyid + n1 + n2 + a1_padded + a2_padded + le
    cobj = CMAC.new(T, ciphermod=AES)
    cobj.update(message_0)
    mackey = cobj.digest()

    # Compute LTK (Counter = 1)
    counter_1 = b'\x01'  # Counter = 1
    message_1 = counter_1 + keyid + n1 + n2 + a1_padded + a2_padded + le
    cobj = CMAC.new(T, ciphermod=AES)
    cobj.update(message_1)
    ltk = cobj.digest()

    return mackey, ltk

def f6(w, n1, n2, r, iocap, a1, a2):
    # w, n1, n2, r, iocap, a1, a2 are types of bytes, the return value should be type of bytes
    # Ensure A1 and A2 are 56 bits (7 bytes), padding as needed
    a1_padded = a1.rjust(7, b'\x00')
    a2_padded = a2.rjust(7, b'\x00')
    m = n1 + n2 + r + iocap + a1_padded + a2_padded
    cobj = CMAC.new(w, ciphermod=AES)
    cobj.update(m)
    return cobj.digest()


# Convert hex strings to bytes
def hex_to_bytes(hex_string):
    return bytes.fromhex(hex_string.replace(" ", ""))

# Sample data for f4 function
u = hex_to_bytes("20b003d2f297be2c5e2c83a7e9f9a5b9eff49111acf4fddbcc0301480e359de6")
v = hex_to_bytes("55188b3d32f6bb9a900afcfbeed4e72a59cb9ac2f19d7cfb6b4fdd49f47fc5fd")
x = hex_to_bytes("d5cb8454d177733effffb2ec712baeab")
z = bytes([0x00])  # Z is 0x00

# Call the f4 function with sample data
result_f4 = f4(u, v, x, z)

# Print the result in hexadecimal format
print("f4 result:", result_f4.hex())

# Sample data for f5 function
w = hex_to_bytes("ec0234a357c8ad05341010a60a397d9b99796b13b4f866f1868d34f373bfa698")
n1 = hex_to_bytes("d5cb8454d177733effffb2ec712baeab")
n2 = hex_to_bytes("a6e8e7cc25a75f6e216583f7ff3dc4cf")
a1 = hex_to_bytes("0056123737bfce")
a2 = hex_to_bytes("00a713702dcfc1")

# Call the f5 function with sample data
mackey, ltk = f5(w, n1, n2, a1, a2)

# Print the results in hexadecimal format
print("f5 MacKey:", mackey.hex())
print("f5 LTK:", ltk.hex())


# Sample data for f6 function
w = hex_to_bytes("2965f176a1084a02fd3f6a20ce636e20")
n1 = hex_to_bytes("d5cb8454d177733effffb2ec712baeab")
n2 = hex_to_bytes("a6e8e7cc25a75f6e216583f7ff3dc4cf")
r = hex_to_bytes("12a3343bb453bb5408da42d20c2d0fc8")
iocap = hex_to_bytes("010102")
a1 = hex_to_bytes("0056123737bfce")
a2 = hex_to_bytes("00a713702dcfc1")

# Call the f6 function with sample data
result_f6 = f6(w, n1, n2, r, iocap, a1, a2)

# Print the result in hexadecimal format
print("f6 result:", result_f6.hex())
