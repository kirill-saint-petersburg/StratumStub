# coinb1 = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff55530b2f503253482f627463642f047071035f08fabe6d6d00000000014d2a2800000000014d293000000000014d288000000000014d27980100000000000000"
# coinb2 = "0d2f6e6f64655374726174756d2f000000000205000000000000001976a914b4840abcf82473582c60d4d91fa4355ea6d6cff588ac05000000000000001976a914f06c22b28563d9f96e3c37fd05d77cfc4a12d1e588ac00000000"
# extranonce1 = "10000002"
# extranonce2 = "00000000"

# coinbase = coinb1  + extranonce1 + extranonce2 + coinb2
# merkleRoot = hashlib.sha256(hashlib.sha256(binascii.unhexlify(coinbase)).digest()).hexdigest() => b'9af1f0187ed3f51767dc900c3864a786ee4a3776b2a473435f887c355261e3af'

import socket
import json
import pprint

def server_program():
    # get the hostname
    #host = socket.gethostname()
    host = '0.0.0.0'
    port = 3333  # initiate port no above 1024

    server_socket = socket.socket()  # get instance
    # look closely. The bind() function takes tuple as argument
    server_socket.bind((host, port))  # bind host address and port together

    # configure how many client the server can listen simultaneously
    server_socket.listen(2)
    conn, address = server_socket.accept()  # accept new connection
    print("Connection from: " + str(address))

    responses1 = {'mining.subscribe': [{'id': None, 'result': [[['mining.set_difficulty', 'deadbeefcafebabe0300000000000000'], ['mining.notify', 'deadbeefcafebabe0300000000000000']], '10000002', 4], 'error': None}],
                  'mining.authorize': [{'id': None, 'method': 'mining.set_difficulty', 'params': [10]},
                                       {'id': None, 'method': 'mining.notify', 'params': ['5b', 'c029e228ade1e6a6503cab5239f690975fb4e221257002ed0804d60700000000', '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff55530b2f503253482f627463642f047071035f08fabe6d6d00000000014d2a2800000000014d293000000000014d288000000000014d27980100000000000000', '0d2f6e6f64655374726174756d2f000000000205000000000000001976a914b4840abcf82473582c60d4d91fa4355ea6d6cff588ac05000000000000001976a914f06c22b28563d9f96e3c37fd05d77cfc4a12d1e588ac00000000', [], '20000000', '207fffff', '5f037170', True]},
                                       {'id': None, 'result': True, 'error': None}],
                  'mining.submit':    [{'id': None, 'result': True, 'error': None}]}

    responses2 = {'mining.subscribe': [{'id': None, 'error': None, 'result': [['mining.notify', 'ae6812eb4cd7735a302a8a9dd95cf71f'], 'f8002c90', 4]}],
                  'mining.authorize': [{'id': None, 'params': [32], 'method': 'mining.set_difficulty'},
                                       {'id': None, 'params': ['b3ba', '7dcf1304b04e79024066cd9481aa464e2fe17966e19edf6f33970e1fe0b60277', '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff270362f401062f503253482f049b8f175308', '0d2f7374726174756d506f6f6c2f000000000100868591052100001976a91431482118f1d7504daf1c001cbfaf91ad580d176d88ac00000000', ['57351e8569cb9d036187a79fd1844fd930c1309efcd16c46af9bb9713b6ee734', '936ab9c33420f187acae660fcdb07ffdffa081273674f0f41e6ecc1347451d23'], '00000002', '1b44dfdb', '53178f9b', True], 'method': 'mining.notify'},
                                       {'id': None, 'result': True, 'error': None}],
                  'mining.submit':    [{'id': None, 'result': True, 'error': None}]}

    pp = pprint.PrettyPrinter(indent=2)

    responses = responses1

    sub_details,extranonce1,extranonce2_size = responses['mining.subscribe'][0]['result']
    job_id_server,prevhash,coinb1,coinb2,merkle_branch,version,nbits,ntime,clean_jobs=list(filter(lambda m: 'method' in m and m['method'] == 'mining.notify', responses['mining.authorize']))[0]['params']

    while True:
        # receive data stream. it won't accept data packet greater than 1024 bytes
        data = conn.recv(4096).decode()

        if not data:
            # if data is not received break
            break

        request = json.loads(str(data))

        print('\nRequest:\n')
        pp.pprint(request)

        if request['method'] == 'mining.submit':
            print('\nShare has been found out.\n')
            user,job_id_client,extranonce2,nonce,ntime=request['params']
            responses['mining.submit'][0]['result'] = job_id_server == job_id_client

        for response in responses[request['method']]:
            if "result" in response:
                response['id'] = request['id']

            print('\nResponse:\n')
            pp.pprint(response)

            payload = (json.dumps(response) + '\n').encode()

            totalsent = 0
            while totalsent < len(payload):
                sent = conn.send(payload[totalsent:])
                if sent == 0:
                    raise RuntimeError("socket connection broken")
                totalsent = totalsent + sent

        if request['method'] == 'mining.submit':
            print('\nStop mining.\n')
            break

    conn.close()  # close the connection

if __name__ == '__main__':
    server_program()
