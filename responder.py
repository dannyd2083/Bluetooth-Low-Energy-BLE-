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
    # TODO1: Finish f4()
    # u, v, x, z are types of bytes, the return value should be type of bytes
    return b'\x00'

def f5(w, n1, n2, a1, a2):
    salt = b'\x6C\x88\x83\x91\xAA\xF5\xA5\x38\x60\x37\x0B\xDB\x5A\x60\x83\xBE'
    keyid = b'\x62\x74\x6c\x65'

    # TODO2: Finish f5()
    # w, n1, n2, a1, a2 are types of bytes, the return value should be tuple of bytes (mackey, ltk)

    return (mackey, ltk)

def f6(w, n1, n2, r, iocap, a1, a2):
    # TODO3: Finish f6()
    # w, n1, n2, r, iocap, a1, a2 are types of bytes, the return value should be type of bytes

    return b'\x00'

def derive_session_key(skd_p, skd_c, ltk):
    # TODO8: Finish derive_session_key()
    # skd_p, sdk_c, and ltk are types of bytes, the return value should be type of bytes
    # session_key = AES_ECB(LTK, SKD)
    return b'\x00'

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
        iocap_a = #TODO4

        # Send pairing response
        pair_rsp = #TODO4
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
            public_key_bytes = #TODO5
            conn.send(public_key_bytes)
            log.info(f'Send public key:{public_key_bytes.hex()}')

            # Calculate DHkey
            dhkey = #TODO5
            log.info(f'DHkey:{dhkey.hex()}')

            # TODO6: Finish pairing Phase 2, authentication phase 1
            # Generate random number Nb
            Nb = #TODO6

            # Calculate Cb
            Cb = #TODO6

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
                (mackey, ltk) = #TODO7

                # Calculate Eb
                Eb = #TODO7

                # Receive Ea from initiator and check Ea
                Ea_bytes = conn.recv()
                log.info(f'Received Ea:{Ea_bytes.hex()}')

                if Ea_bytes[0] == PAIR_CONF_OPCODE:
                    Ea = Ea_bytes[1:]
                    Ea_calculated = #TODO7
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
                        iv_p = #TODO8
                        skd_p = #TODO8
                        conn.send(iv_p + skd_p)
                        log.info(f'Send IV_P + SKD_P:{iv_p.hex() + skd_p.hex()}')

                        session_iv = #TODO8
                        session_key = derive_session_key(skd_p, skd_c, ltk)

                        enc_data = conn.recv()
                        log.info(f'Received encrypted data:{enc_data.hex()}')

                        data = # TODO9: decrypted enc_data

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
