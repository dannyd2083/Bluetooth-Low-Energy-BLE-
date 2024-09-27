#!/usr/bin/env python3
import logging
import secrets

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

SECRET = b'This is A VERY VERY HARD HOMEWORK'


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

def compute_dhkey(private_key, peer_public_key):
    # Calculate the shared secret (DHKey) using the private key and the peer's public key
    shared_dhkey = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_dhkey

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
    return conbj.digest()

def derive_session_key(skd_p, skd_c, ltk):
    # TODO8: Finish derive_session_key()
    # skd_p, sdk_c, and ltk are types of bytes, the return value should be type of bytes
    # session_key = AES_ECB(LTK, SKD)
    skd = skd_p + skd_c
    cipher = AES.new(ltk, AES.MODE_ECB)
    session_key = cipher.encrypt(skd)
    return session_key


def create_pairing_request():
    # Fields for the pairing request

    code = PAIR_REQ_OPCODE.to_bytes(1, 'big')  # 1 byte for opcode
    io_capability = IOCap.to_bytes(1, 'big')  # 1 byte for IO capability
    oob_flag = OOBDATA.to_bytes(1, 'big')  # 1 byte for OOB flag
    auth_flag = AuthReq.to_bytes(1, 'big')  # 1 byte for authentication requirements
    encryption_key_size = MAXKEYSIZE.to_bytes(1, 'big')  # 1 byte for max encryption key size
    initiator_key_distribution = INIT_KEY_DISTRIBUTION.to_bytes(1, 'big')  # 1 byte for key distribution
    responder_key_distribution = RSP_KEY_DISTRIBUTION.to_bytes(1, 'big')  # 1 byte for key distribution

    # Combine the fields into a pairing response packet

    pairing_request = (code + io_capability + oob_flag + auth_flag +
                       encryption_key_size + initiator_key_distribution + responder_key_distribution)

    print(f'created pairing_request {pairing_request.hex()}')

    return pairing_request


def deserialize_key(key):
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), key)


def serialize_key(key):
    return key.public_bytes(encoding=serialization.Encoding.X962,
                                  format=serialization.PublicFormat.CompressedPoint)

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
            iocap_b = pair_rsp[1:4]

            # Generate public/private key pair
            (private_key, public_key) = generate_public_private_key_pair()
            # TODO5: Finish pairing Phase 2, public key exchange
            # Send public key to responder
            #TODO5
            x_bytes = public_key.x.to_bytes(32, 'big')
            y_bytes = public_key.y.to_bytes(32, 'big')
            public_key_raw = x_bytes+ y_bytes
            public_key_bytes = PAIR_PUB_KEY.to_bytes(1, 'big') + x_bytes+ y_bytes
            conn.send(public_key_bytes)
            log.info(f'Send public key:{public_key_bytes.hex()}')

            # Receive public key from responder
            pair_pub_key = conn.recv()
            log.info(f'Received public key:{pair_pub_key.hex()}')
            if pair_pub_key[0] == PAIR_PUB_KEY:
                # Get public key from responder
                responder_pub_key_x = pair_pub_key [1:33]
                responder_pub_key_y = pair_pub_key [33:65]
                responder_pub_key_bytes = responder_pub_key_x + responder_pub_key_y
                x = int.from_bytes(responder_pub_key_x, 'big')
                y = int.from_bytes(responder_pub_key_y, 'big')
                # Calculate DHkey
                #TODO5
                peer_public_key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
                dhkey = compute_dhkey(private_key,peer_public_key)
                log.info(f'DHkey:{dhkey.hex()}')

                # Receive confirmation (Cb) from responder
                # TODO6: Finish pairing Phase 2, authentication phase 1
                Cb_bytes = conn.recv()
                log.info(f'cb Received confirmation:{Cb_bytes.hex()}')

                if Cb_bytes[0] == PAIR_CONF_OPCODE:
                    Cb_received = Cb_bytes[1:]
                    # Generate random number Na

                    # Send random number Na to responder
                    #TODO6
                    Na = secrets.token_bytes(16)
                    Na_bytes = PAIR_RAND_OPCODE.to_bytes(1, 'big') + Na #TODO6
                    conn.send(Na_bytes)
                    log.info(f'Send random number na:{Na_bytes.hex()}')

                    # Receive random number (Nb) from responder
                    Nb_bytes = conn.recv()
                    log.info(f'Received random number nb:{Nb_bytes.hex()}')
                    if Nb_bytes[0] == PAIR_RAND_OPCODE:

                        # Calculate Cb
                        #TODO6
                        Nb = Nb_bytes[1:]
                        log.info(f'res public key:{responder_pub_key_bytes.hex()}')
                        log.info(f'init public_key:{public_key_bytes.hex()}')
                        log.info(f'nb:{Nb_bytes.hex()}')
                        Cb_calculated = f4(responder_pub_key_x,public_key_raw,Nb,b'\x00') #TODO6
                        log.info(f'cb calculated:{Cb_calculated.hex()}')

                        if Cb_calculated == Cb_received:
                            # Skip user confirmation value calculation
                            # because it's always successful in JW pairing
                            # Calculate mackey and ltk
                            # Add b'\x00' (address type) to MAC_ADDR and MAC_ADDR_responder
                            # TODO7: Finish pairing Phase 2, authentication phase 2

                            log.info(f'na initiator side:{Na.hex()}')
                            log.info(f'nb initiator side:{Nb.hex()}')
                            (mackey, ltk) =  f5(dhkey,Na,Nb,MAC_ADDR,MAC_ADDR_responder)#TODO7

                            log.info(f'initiator mackey:{mackey.hex()}')
                            log.info(f'initiator ltk:{ltk.hex()}')
                            # Calculate Ea and send it to responder
                            #TODO7
                            Ea = f6(mackey,Na,Nb,b'\x00'.rjust(16, b'\x00'),p8(IOCap)+p8(OOBDATA)+p8(AuthReq),MAC_ADDR,MAC_ADDR_responder) #TODO7
                            conn.send(p8(PAIR_CONF_OPCODE) + Ea)
                            log.info(f'Send confirmation:{Ea.hex()}')

                            # Receive confirmation Eb from responder
                            Eb_bytes = conn.recv()
                            log.info(f'Received confirmation:{Eb_bytes.hex()}')
                            if Eb_bytes[0] == PAIR_CONF_OPCODE:
                                Eb = Eb_bytes[1:]
                                #TODO7
                                Eb_calculated =  f6(mackey,Na,Nb,b'\x00'.rjust(16, b'\x00'),iocap_b,MAC_ADDR_responder,MAC_ADDR) #DUMMY
                                log.info(f'Eb_calculate:{Eb_calculated.hex()}')
                                log.info(f'Eb:{Eb.hex()}')
                                if Eb_calculated == Eb:
                                    print('Pairing successful, now distribute keys')
                                    # TODO8: Finish pairing Phase 3
                                    # Generate IV_C and SKD_C and send them to responder
                                    #TODO8
                                    iv_c =  secrets.token_bytes(4) #TODO8
                                    #TODO8
                                    skd_c = secrets.token_bytes(8) #TODO8
                                    conn.send(iv_c + skd_c)
                                    log.info(f'Send IV_C + SKD_C:{iv_c.hex() + skd_c.hex()}')

                                    # Receive IV_P and SKD_P from responder
                                    ivskd_p = conn.recv()
                                    log.info(f'Received IV_P + SKD_P:{ivskd_p.hex()}')
                                    iv_p = ivskd_p[:4]
                                    skd_p = ivskd_p[4:]
                                    #TODO8
                                    session_iv =  iv_p + iv_c #DUMMY
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
