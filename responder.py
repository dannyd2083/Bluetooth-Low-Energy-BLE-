#!/usr/bin/env python3
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
AuthReq = 0
MAXKEYSIZE = 16
OOBDATA = 0
MAC_ADDR = b'\x22\x33\x44\x55\x66\x77'
INIT_KEY_DISTRIBUTION = 0
RSP_KEY_DISTRIBUTION = 0

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

    # Compute MacKey (counter = 0)
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
    m = n1 + n2 + r + iocap + a1_padded + a2_padded
    conbj = CMAC.new(w, ciphermod=AES)
    conbj.update(m)
    return cobj.digest()

def derive_session_key(skd_p, skd_c, ltk):
    # TODO8: Finish derive_session_key()
    # skd_p, sdk_c, and ltk are types of bytes, the return value should be type of bytes
    # session_key = AES_ECB(LTK, SKD)
    return b'\x00'


def create_pairing_response():
    # Fields for the pairing response
    code = PAIR_RSP_OPCODE
    io_capability = IOCap  # NoInputNoOutput for Just Works
    oob_flag = OOBDATA  # No OOB data available
    auth_flag = AuthReq  # No MITM protection required
    encryption_key_size = MAXKEYSIZE  # Max encryption key size (e.g., 7 bytes)
    initiator_key_distribution = INIT_KEY_DISTRIBUTION  # LTK distributed by initiator
    responder_key_distribution = RSP_KEY_DISTRIBUTION # LTK distributed by responder

    # Combine the fields into a pairing response packet
    pairing_response = code+ io_capability + oob_flag + auth_flag + encryption_key_size + \
                       initiator_key_distribution + responder_key_distribution

    return bytearray(pairing_response)


def start_jw_pairing(conn):
    # Exchange MAC addresses
    MAC_init = conn.recv()
    log.info(f'Received MAC:{MAC_init.hex()}')

    conn.send(MAC_ADDR)
    log.info(f'Send MAC:{MAC_ADDR.hex()}')

    # Receive pairing request
    # TODO4: Finish pairing Phase 1
    pair_req = conn.recv()
    log.info(f'Received pairing request:{pair_req.hex()}')

    if pair_req[0] == PAIR_REQ_OPCODE:
        # Get iocap_a
        iocap_a = pair_req[1]

        # Send pairing response
        pair_rsp = create_pairing_response()
        conn.send(pair_rsp)
        log.info(f'Send pairing response:{pair_rsp.hex()}')

        # Receive public key from initiator
        pair_pub_key = conn.recv()
        log.info(f'Received public key:{pair_pub_key.hex()}')

        if pair_pub_key[0] == PAIR_PUB_KEY:
            # Get public key from initiator
            public_key_initor_x = pair_pub_key[1:33]
            public_key_initor_y = pair_pub_key[33:65]

            # Generate public/private key pair
            (private_key, public_key) = generate_public_private_key_pair()
            # TODO5: Finish pairing Phase 2, public key exchange

            # Send public key to initiator
            #TODO5
            public_key_bytes = b'\x01\x00' #DUMMY
            conn.send(public_key_bytes)
            log.info(f'Send public key:{public_key_bytes.hex()}')

            # Calculate DHkey
            #TODO5
            dhkey = b'\x01\x00' #DUMMY
            log.info(f'DHkey:{dhkey.hex()}')

            # TODO6: Finish pairing Phase 2, authentication phase 1
            # Generate random number Nb
            Nb = b'\x01\x00' #DUMMY

            # Calculate Cb
            Cb = b'\x01\x00' #DUMMY

            # Send Cb to initiator
            Cb_bytes = p8(PAIR_CONF_OPCODE) + Cb
            conn.send(Cb_bytes)
            log.info(f'Send Cb:{Cb_bytes.hex()}')

            # Receive Na from initiator
            Na_bytes = conn.recv()
            log.info(f'Received Na:{Na_bytes.hex()}')
            if Na_bytes[0] == PAIR_RAND_OPCODE:
                # Send Nb to initiator
                Na = Na_bytes[1:]
                Nb_bytes = p8(PAIR_RAND_OPCODE) + Nb
                conn.send(Nb_bytes)
                log.info(f'Send Nb:{Nb_bytes.hex()}')

                # Skip user confirmation value calculation
                # because it's always successful in JW pairing
                # Calculate mackey and ltk
                # Add b'\x00' (address type) to MAC_ADDR and MAC_ADDR_responder
                # TODO7: Finish pairing Phase 2, authentication phase 2
                (mackey, ltk) = (b'\x01\x00', b'\x01\x00') #DUMMY

                # Calculate Eb
                #TODO7
                Eb = b'\x01\x00' #DUMMY

                # Receive Ea from initiator and check Ea
                Ea_bytes = conn.recv()
                log.info(f'Received Ea:{Ea_bytes.hex()}')

                if Ea_bytes[0] == PAIR_CONF_OPCODE:
                    Ea = Ea_bytes[1:]
                    #TODO7
                    Ea_calculated = b'\x01\x00' #DUMMY
                    if Ea == Ea_calculated:
                        conn.send(p8(PAIR_CONF_OPCODE) + Eb)
                        log.info(f'Send Eb:{Eb.hex()}')
                        print('Pairing successful, now distribute keys')

                        # TODO8 Finish pairing Phase 3
                        # Receive IV_C and SKD_C from responder
                        ivskd_c = conn.recv()
                        log.info(f'Received IV_C + SKD_C:{ivskd_c.hex()}')
                        iv_c = ivskd_c[:4]
                        skd_c = ivskd_c[4:]

                        # Generate IV_P and SKD_P and send them to responder
                        #TODO8
                        iv_p = b'\x01\x00' #DUMMY
                        #TODO8
                        skd_p = b'\x01\x00' #DUMMY
                        conn.send(iv_p + skd_p)
                        log.info(f'Send IV_P + SKD_P:{iv_p.hex() + skd_p.hex()}')
                        #TODO8
                        session_iv = b'\x01\x00' #DUMMY
                        session_key = derive_session_key(skd_p, skd_c, ltk)

                        enc_data = conn.recv()
                        log.info(f'Received encrypted data:{enc_data.hex()}')
                        #TODO9
                        data = b'\x01\x00' #DUMMY

                        print('Decrypted data:', data.decode('utf-8'))

                    else:
                        print('Pairing failed')
                else:
                    print('Invalid confirmation')

            else:
                print('Invalid random number request')

        else:
            print('Invalid public key request')

    else:
        print('Invalid pairing request')

def start_server(host='127.0.0.1', port=65432):
    server = listen(port, bindaddr=host)
    print(f'Server listening on {host}:{port}')

    connection = server.wait_for_connection()
    print(f'Connected by {connection.rhost}:{connection.rport}')

    start_jw_pairing(connection)

    connection.close()

if __name__ == "__main__":
    start_server()
