import asyncore
import json
import hashlib
import binascii
import pprint

class StratumResponseStub(object):
    @staticmethod
    def diff_to_target(diff):
        target_octets = ['00000000', '00000000', '00000000', '00000000', '00000000', '00000000', '00000000', '00000000']
        shift = (diff.bit_length() - 1) // 32 + 1
        target_octets[shift] = '{0:0{1}x}'.format(int((4294901760.0 / diff) * (0x100000000 ** shift)) >> 32, 8) #hex(int((4294901760.0 / diff) * (0x100000000 ** shift)) >> 32)[2:]
        return binascii.unhexlify(''.join(target_octets))

    def __init__(self, extranonce1_int, difficulty):
        self._responses = {'mining.configure': [{'id': None, 'result': {'version-rolling': True, 'version-rolling.mask': '5fffe000'}}],
                           'mining.subscribe': [{'id': None, 'result': [[['mining.set_difficulty', 'deadbeefcafebabe0300000000000000'], ['mining.notify', 'deadbeefcafebabe0300000000000000']], '10000002', 4], 'error': None}],
                           'mining.authorize': [{'id': None, 'method': 'mining.set_difficulty', 'params': [131072]},
                                                {'id': None, 'method': 'mining.notify',
                                                 'params':
                                                    [
                                                        '10000002',
                                                        'c029e228ade1e6a6503cab5239f690975fb4e221257002ed0804d60700000000',
                                                        '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff55530b2f503253482f627463642f047071035f08fabe6d6d00000000014d2a2800000000014d293000000000014d288000000000014d27980100000000000000',
                                                        '0d2f6e6f64655374726174756d2f000000000205000000000000001976a914b4840abcf82473582c60d4d91fa4355ea6d6cff588ac05000000000000001976a914f06c22b28563d9f96e3c37fd05d77cfc4a12d1e588ac00000000',
                                                        [],
                                                        '20000000',
                                                        '207fffff',
                                                        '5f037170',
                                                        True
                                                    ]
                                                },
                                                {'id': None, 'result': True, 'error': None}],
                           'mining.submit':    [{'id': None, 'result': True, 'error': None}]}

        self._extranonce1_int = extranonce1_int
        self._difficulty = difficulty

        self._responses['mining.subscribe'][0]['result'][1] = f'{self._extranonce1_int:08x}'

        for l in filter(lambda m: 'method' in m and m['method'] == 'mining.set_difficulty', self._responses['mining.authorize']):
            l['params'][0] = self._difficulty

    @property
    def responses(self):
        return self._responses

    def is_block_valid(self, extranonce2, ntime, nonce):
        _extranonce1 = self._responses['mining.subscribe'][0]['result'][1]
        _,_prevhash,_coinb1,_coinb2,_merkle_branch,_version,_nbits,*_ = list(filter(lambda m: 'method' in m and m['method'] == 'mining.notify', self._responses['mining.authorize']))[0]['params']
        [diff] = [int(list(filter(lambda m: 'method' in m and m['method'] == 'mining.set_difficulty', self._responses['mining.authorize']))[0]['params'][0])]
        merkle_root = hashlib.sha256(hashlib.sha256(binascii.unhexlify(f"{_coinb1}{_extranonce1}{extranonce2}{_coinb2}")).digest()).digest()
        for leaf in _merkle_branch:
            merkle_root = hashlib.sha256(hashlib.sha256(merkle_root + binascii.unhexlify(leaf)).digest()).digest()

        merkle_root = binascii.hexlify(merkle_root).decode()
        version_le = binascii.hexlify(binascii.unhexlify(_version)[::-1]).decode("utf-8")
        prevhash_le = (b''.join([binascii.hexlify(binascii.unhexlify(_prevhash)[i:i+4][::-1]) for i in range(0,len(binascii.unhexlify(_prevhash)),4)])).decode("utf-8")
        ntime_le = binascii.hexlify(binascii.unhexlify(ntime)[::-1]).decode("utf-8")
        nbits_le = binascii.hexlify(binascii.unhexlify(_nbits)[::-1]).decode("utf-8")
        nonce_le = binascii.hexlify(binascii.unhexlify(nonce)[::-1]).decode("utf-8")
        blockheader = f"{version_le}{prevhash_le}{merkle_root}{ntime_le}{nbits_le}{nonce_le}"
        hash = hashlib.sha256(hashlib.sha256(binascii.unhexlify(blockheader)).digest()).digest()[::-1]
        target = StratumResponseStub.diff_to_target(diff)
        print("hash  : " + binascii.hexlify(hash).decode())
        print("target: " + binascii.hexlify(target).decode())
        print(f"extranonce1: {_extranonce1}, extranonce2: {extranonce2}, nonce: {nonce}")
        with open('share.log', 'a+') as log_file:
            log_file.write(f"{_extranonce1} {extranonce2} {nonce}\n")

        return hash < target

    def validate_block(self, *args, **kwargs):
        self.responses['mining.submit'][0]['result'] = self.is_block_valid(*args, **kwargs)

class StratumRequestHandler(asyncore.dispatcher_with_send):

    def handle_read(self):

        data = self.recv(8192).decode()

        if not data:
            # if data is not received break
            return

        request = json.loads(str(data))

        pp = pprint.PrettyPrinter(indent=2)

        print('\nRequest:\n')
        pp.pprint(request)

        stub = StratumResponseStub(0x1000_0002, 0x02) #0x0002_0000

        if request['method'] not in stub.responses:
            return

        if request['method'] == 'mining.submit':
            print('\nShare has been found out.\n')
            stub.validate_block(*request['params'][2:5])

        for response in stub.responses[request['method']]:
            if 'result' in response:
                response['id'] = request['id']

            print('\nResponse:\n')
            pp.pprint(response)

            self.send((json.dumps(response) + '\n').encode())

class StratumStubServer(asyncore.dispatcher):

    def __init__(self, host, port):
        asyncore.dispatcher.__init__(self)
        self.create_socket()
        self.set_reuse_addr()
        self.bind((host, port))
        self.listen(5)

    def handle_accepted(self, sock, addr):
        print('Incoming connection from %s' % repr(addr))
        StratumRequestHandler(sock)

if __name__ == '__main__':
    server = StratumStubServer('0.0.0.0', 3333)
    asyncore.loop()
