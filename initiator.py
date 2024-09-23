#!/usr/bin/env python3
import logging

from pwn import *

from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from Crypto.Random import get_random_bytes

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# Packet types
PAIR_REQ_OPCODE = 0x01
PAIR_RSP_OPCODE = 0x02
PAIR_CONF_OPCODE = 0x03
PAIR_RAND_OPCODE = 0x04
PAIR_PUB_KEY = 0x0c

IOCap = 0x03
MAXKEYSIZE = 16
OOBDATA = 0
AuthReq = 0
MAC_ADDR = b'\x11\x22\x33\x44\x55\x66'
INIT_KEY_DISTRIBUTION = 0
RSP_KEY_DISTRIBUTION = 0

SECRET = b'This is a secret message'


# Create and configure logger
logger = logging.getLogger('my_logger')
logger.setLevel(logging.DEBUG)  # Logger level

# Create console handler for INFO level
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(console_formatter)

# Add handlers to the logger
logger.addHandler(console_handler)


def generate_public_private_key_pair():
    # Generate a random ECC private key
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Derive the corresponding public key
    public_key = private_key.public_key()

    # Extract the x and y coordinates from the public key
    public_numbers = public_key.public_numbers()

    return (private_key, public_numbers)

def f4(u, v, x, z):
    # u, v, x, z are types of bytes, the return value should be type of bytes
    msg = u+v+z
    cobj = CMAC.new(x,ciphermod= AES)
    cobj.update(msg)
    return cobj.digest()

def f5(w, n1, n2, a1, a2):
    salt = b'\x6C\x88\x83\x91\xAA\xF5\xA5\x38\x60\x37\x0B\xDB\x5A\x60\x83\xBE'
    keyid = b'\x62\x74\x6c\x65'
    cobj = CMAC.new(salt, ciphermod=AES)
    cobj.update(w)
    T = cobj.digest()
    le = b'\x01\x00' #256
    # Ensure A1 and A2 are 56 bits (7 bytes), padding as needed
    a1_padded = a1.rjust(7, b'\x00')
    a2_padded = a2.rjust(7, b'\x00')

    #Compute MacKey (counter = 0)
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
    # w, n1, n2, a1, a2 are types of bytes, the return value should be tuple of bytes (mackey, ltk)

def f6(w, n1, n2, r, iocap, a1, a2):
    # TODO3: Finish f6()
    # w, n1, n2, r, iocap, a1, a2 are types of bytes, the return value should be type of bytes
    # Ensure A1 and A2 are 56 bits (7 bytes), padding as needed
    a1_padded = a1.rjust(7, b'\x00')
    a2_padded = a2.rjust(7, b'\x00')
    m = n1+n2+r+iocap+a1_padded+a2_padded
    conbj = CMAC.new(w, ciphermod=AES)
    conbj.update(m)
    return cobj.digest()

def derive_session_key(skd_p, skd_c, ltk):
    # TODO8: Finish derive_session_key()
    # skd_p, sdk_c, and ltk are types of bytes, the return value should be type of bytes
    # session_key = AES_ECB(LTK, SKD)
    return b'\x00'


def create_pairing_request():
    # Fields for the pairing request
    code = PAIR_REQ_OPCODE
    io_capability = IOCap  # NoInputNoOutput for Just Works
    oob_flag = OOBDATA  # No OOB data available
    auth_flag = AuthReq  # No MITM protection required
    encryption_key_size = MAXKEYSIZE  # Max encryption key size (e.g., 7 bytes)
    initiator_key_distribution = INIT_KEY_DISTRIBUTION  # LTK distributed by initiator
    responder_key_distribution = RSP_KEY_DISTRIBUTION  # LTK distributed by responder

    # Combine the fields into a pairing response packet
    pairing_request = code + io_capability + oob_flag + auth_flag + encryption_key_size + \
                       initiator_key_distribution + responder_key_distribution

    return bytearray(pairing_request)

def start_jw_pairing(host='127.0.0.1', port=65432):
    conn = remote(host, port)
#    print(f'Connected to server at {host}:{port}')

    try:
        # Exchange MAC addresses
        conn.send(MAC_ADDR)
        log.info(f'Send MAC:{MAC_ADDR.hex()}')

        MAC_ADDR_responder = conn.recv()
        log.info(f'Received MAC:{MAC_ADDR_responder.hex()}')

        # Send pairing request to responder
        # TODO4: Finish pairing Phase 1
        pair_req = create_pairing_request()
        conn.send(pair_req)
        log.info(f'Send pairing request:{pair_req.hex()}')

        # Receive pairing response
        pair_rsp = conn.recv()
        log.info(f'Received pairing response:{pair_rsp.hex()}')

        if pair_rsp[0] == PAIR_RSP_OPCODE:
            # Get iocap_b
            iocap_b = #TODO4

            # Generate public/private key pair
            (private_key, public_key) = generate_public_private_key_pair()
            # TODO5: Finish pairing Phase 2, public key exchange

            # Send public key to responder
            pair_pub_key = #TODO5
            conn.send(pair_pub_key)
            log.info(f'Send public key:{pair_pub_key.hex()}')

            # Receive public key from responder
            pair_pub_key = conn.recv()
            log.info(f'Received public key:{pair_pub_key.hex()}')

            if pair_pub_key[0] == PAIR_PUB_KEY:
                # Get public key from responder
                responder_pub_key_x = pair_pub_key[1:33]
                responder_pub_key_y = pair_pub_key[33:65]

                # Calculate DHkey
                dhkey = #TODO5
                log.info(f'DHkey:{dhkey.hex()}')

                # Receive confirmation (Cb) from responder
                # TODO6: Finish pairing Phase 2, authentication phase 1
                Cb_bytes = conn.recv()
                log.info(f'Received confirmation:{Cb_bytes.hex()}')

                if Cb_bytes[0] == PAIR_CONF_OPCODE:
                    Cb_received = Cb_bytes[1:]
                    # Generate random number Na

                    # Send random number Na to responder
                    Na_bytes = #TODO6
                    conn.send(Na_bytes)
                    log.info(f'Send random number:{Na_bytes.hex()}')

                    # Receive random number (Nb) from responder
                    Nb_bytes = conn.recv()
                    log.info(f'Received random number:{Nb_bytes.hex()}')
                    if Nb_bytes[0] == PAIR_RAND_OPCODE:

                        # Calculate Cb
                        Cb_calculated = #TODO6

                        if Cb_calculated == Cb_received:
                            # Skip user confirmation value calculation
                            # because it's always successful in JW pairing
                            # Calculate mackey and ltk
                            # Add b'\x00' (address type) to MAC_ADDR and MAC_ADDR_responder
                            # TODO7: Finish pairing Phase 2, authentication phase 2
                            (mackey, ltk) = #TODO7

                            # Calculate Ea and send it to responder
                            Ea = #TODO7
                            conn.send(p8(PAIR_CONF_OPCODE) + Ea)
                            log.info(f'Send confirmation:{Ea.hex()}')

                            # Receive confirmation Eb from responder
                            Eb_bytes = conn.recv()
                            log.info(f'Received confirmation:{Eb_bytes.hex()}')

                            if Eb_bytes[0] == PAIR_CONF_OPCODE:
                                Eb = Eb_bytes[1:]
                                Eb_calculated = #TODO7

                                if Eb_calculated == Eb:
                                    print('Pairing successful, now distribute keys')

                                    # TODO8: Finish pairing Phase 3
                                    # Generate IV_C and SKD_C and send them to responder
                                    iv_c = #TODO8
                                    skd_c = #TODO8
                                    conn.send(iv_c + skd_c)
                                    log.info(f'Send IV_C + SKD_C:{iv_c.hex() + skd_c.hex()}')

                                    # Receive IV_P and SKD_P from responder
                                    ivskd_p = conn.recv()
                                    log.info(f'Received IV_P + SKD_P:{ivskd_p.hex()}')
                                    iv_p = ivskd_p[:4]
                                    skd_p = ivskd_p[4:]

                                    session_iv = #TODO8
                                    session_key = derive_session_key(skd_p, skd_c, ltk)

                                    cipher = AES.new(session_key, AES.MODE_CCM, nonce=session_iv)
                                    # default tag length is 16
                                    enc_data, tag = cipher.encrypt_and_digest(SECRET)

                                    conn.send(enc_data + tag)
                                    log.info(f'Send encrypted data:{enc_data.hex() + tag.hex()}')

                            else:
                                print('Invalid confirmation response')
                                exit(1)
                        else:
                            print('Confirmation not equal')
                            exit(0)
                    else:
                        print('Invalid random number response')
                        exit(1)

                    ra = 0
                    rb = 0

                else:
                    print('Invalid confirmation response')
                    exit(1)
            else:
                print('Invalid public key response')
                exit(1)
        else:
            print('Invalid pairing response')
            exit(1)

    except KeyboardInterrupt:
        print('\nClient stopped.')
    finally:
        conn.close()

if __name__ == "__main__":
    start_jw_pairing()
