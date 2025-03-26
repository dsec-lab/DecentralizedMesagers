import os
import random
import subprocess
import json
import argparse

from datetime import datetime


bear_token = 'syt_bGVlaG9v_aHvkQBdDkFkBQdRXIMlV_0r0TKF'
input_homeservers_file_path = r'homeservers_sumed_2025_03_23.csv'
not_worked_servers_file_path = r'not_worked_servers.csv'
retrieved_servers_file_path = 'retrieved_servers.csv'
public_rooms_file_path = r'public_rooms.json'
joined_members_threshold = 20


def write_in(data, file_path):
    with open(file_path, 'a') as f:
        f.write(data)
        f.write('\n')
    return


def load_servers(input_homeservers_file_path):
    servers = []
    with open(input_homeservers_file_path) as file:
        for line in file.readlines():
            servers.append(line.strip())
    return list(set(servers))


def load_retrieved_servers(retrieved_servers_file_path):
    retrieved_servers = []
    with open(retrieved_servers_file_path) as file:
        for line in file.readlines():
            server = line.strip()
            retrieved_servers.append(server)
    return list(set(retrieved_servers))

def retrieve_pub_rooms(not_worked_servers, input_hs, retrieved_servers):
    for idx, server in enumerate(input_hs):
        print(f"Process: {idx}/{len(input_hs)} ({idx/len(input_hs):.0%})")
        if server in not_worked_servers:
            print('Retrieving homeserver in Not Worked Server List! Continue: {}'.format(server))
            continue
        if server in retrieved_servers:
            print('The homeserver has been retrieved: {}'.format(server))
            continue

        cmd_retrieve_pub_rooms = [
            'curl', '-X', 'POST',
            "https://matrix.org/_matrix/client/v3/publicRooms?server={}".format(server),
            '-H', '"Accept: application/json"',
            '-H', "Authorization: Bearer {}".format(bear_token),
            '-H', "Content-Type: application/json",
            '-d', '{\"include_all_networks\":false}',
            "--max-time", "5"
        ]
        print('')
        print('Retrieving homeserver: {}'.format(server))
        # print(cmd_retrieve_pub_rooms)
        try:
            pub_rooms_info = subprocess.run(cmd_retrieve_pub_rooms, capture_output=True, text=True, timeout=5)
            if any(err in pub_rooms_info.stdout for err in ["error code", "errcode"]):
                print('error code in retrieving homeserver: {}'.format(server))
                write_in(server, not_worked_servers_file_path)
                continue
            # print(pub_rooms_info.stdout)
            # total_room_count_estimate = json.loads(pub_rooms_info.stdout)['total_room_count_estimate']
            room_chunk = json.loads(pub_rooms_info.stdout)['chunk']
            print("Success in retrieving homeserver {}".format(server))
            for item in room_chunk:
                # print(item)
                with open(public_rooms_file_path, 'a') as file:
                    file.writelines(json.dumps(item))
                    file.write('\n')
            with open(retrieved_servers_file_path, 'a') as f:
                f.write(server)
                f.write('\n')
        except subprocess.TimeoutExpired:
            write_in(server, not_worked_servers_file_path)
            print("Request Timeout Expired!")


def load_rooms(input_rooms_file_path):
    '''
    return room ID list to join in
    :param input_rooms_file_path:
    :return:
    '''
    roomID_list = []
    world_readable_rooms = []
    with open(input_rooms_file_path) as file:
        for pub_rooms_info in file.readlines():
            room_chunk = json.loads(pub_rooms_info.strip())
            room_id = room_chunk['room_id']
            if 'canonical_alias' in room_chunk.keys():
                room_canonical_alias = room_chunk['canonical_alias']
            num_joined_members = room_chunk['num_joined_members']
            if 'join_rule' in room_chunk.keys():
                join_rule = room_chunk['join_rule']  # public, private
                if join_rule == 'public' and num_joined_members > joined_members_threshold:
                    # print(room_id, num_joined_members)
                    roomID_list.append(room_id)
            if 'world_readable' in room_chunk.keys():
                world_readable = room_chunk['world_readable']
                if world_readable is True:
                    print(room_id)
                    world_readable_rooms.append(room_id)
    return list(set(roomID_list)), list(set(world_readable_rooms))


def user_join_rooms(roomID_list):
    userID_list = []
    found_homeservers = []
    for roomID in roomID_list:
        if len(roomID) > 50: continue
        '''
        cmd_join_pub_rooms = [
            'curl', '-X', 'POST',
            "https://matrix.org/_matrix/client/v3/join/{}?server_name=matrix.org&server_name=elsewhere.ca&via=matrix.org&via=elsewhere.ca".format(roomID),
            '-H', '"Accept: application/json"',
            '-H', "Authorization: Bearer {}".format(bear_token),
            '-H', "Content-Type: application/json",
            "--max-time", "30"
        ]
        print("Joining in Room: {}".format(roomID))
        '''
        print()
        print('Retrieve joined members of world_readable room: {}'.format(roomID))
        cmd_joined_members_of_world_readable_room = [
            'curl', '-X', 'GET',
            "https://matrix.org/_matrix/client/v3/rooms/{}/joined_members".format(roomID),
            '-H', '"Accept: application/json"',
            '-H', "Authorization: Bearer {}".format(bear_token)
        ]
        result = subprocess.run(cmd_joined_members_of_world_readable_room, capture_output=True, text=True, timeout=30)
        if 'joined' not in json.loads(result.stdout).keys():
            continue
        for userID, value in json.loads(result.stdout)['joined'].items():
            userID_list.append(userID)
            server_name = userID.split(':')[-1]
            if server_name not in hs_list and server_name not in found_homeservers:
                print('A novel server name founded: {}'.format(server_name))
                found_homeservers.append(server_name)
                today_date = datetime.today().date()
                with open('novel_servers_founded_in_{}.csv'.format(str(today_date)), 'a') as f:
                    f.write(server_name)
                    f.write('\n')
            # else:
            #     print('No novel servers founded.')
    print(list(set(userID_list)))

    return 1


def retrieve_server_IPs(retrieve_servers):
    for idx, server in enumerate(retrieve_servers):
        print(f"Process: {idx}/{len(retrieve_servers)} ({idx / len(retrieve_servers):.0%})")
        today_date = datetime.today().date()
        federation_data_dir = 'federation_tester_data' + '-' + str(today_date)
        if not os.path.isdir(federation_data_dir):
            os.makedirs(federation_data_dir)
        data_path = os.path.join(federation_data_dir, server + '.json')
        try:

            api = 'https://federationtester.matrix.org/api/report?server_name={}'.format(server)
            federation_tester_cmd = 'curl --connect-timeout 5 {api} -H "Accept: application/json"'.format(api=api)
            p = subprocess.Popen(federation_tester_cmd, shell=True, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 encoding='utf-8')
            result = json.dumps(p.communicate()[0])
            result = json.loads(result).strip()
            # result = json.loads(re.sub('\n|\s', '', result))
            # mode 1
            '''
            cmd_retrieve_serverIPs_by_matrix_federation_tester = [
                './matrix-federation-tester/matrix-federation-tester', '-lookup', server
            ]
            result = subprocess.run(cmd_retrieve_serverIPs_by_matrix_federation_tester,
                                capture_output=True, text=True, timeout=10)
            '''
            # print(result.stdout)
            print("Retrieving server: {}".format(server))
            with open(data_path, 'a') as f:
                f.writelines(result)
        except subprocess.TimeoutExpired:
            print("Request Timeout Expired!")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Retrieve Matrix Nodes.')
    parser.add_argument('action', choices=["rooms", "users", "ips"],
                        help='Choose to retrieve public rooms or retrieve users.')
    parser.add_argument('start', default=0, type=int,
                        help='Set start index value.')
    parser.add_argument('end', default=9999999999, type=int,
                        help='Set end index value.')
    args = parser.parse_args()

    hs_list = load_servers(input_homeservers_file_path)
    print('Number of homeservers of the initial file "{}": {}'.format(input_homeservers_file_path,
                                                                  len(set(hs_list))))

    if args.action == 'rooms':
        not_worked_servers = load_servers(not_worked_servers_file_path)
        retrieved_servers = load_retrieved_servers(retrieved_servers_file_path)
        print('*** Number of not worked servers: {} ***'.format(len(not_worked_servers)))
        print('*** Number of retrieved servers: {} ***'.format(len(retrieved_servers)))
        print()
        retrieve_pub_rooms(not_worked_servers, hs_list, retrieved_servers)
    if args.action == 'users':
        _, world_readable_rooms = load_rooms(input_rooms_file_path='public_rooms.json')
        res = user_join_rooms(world_readable_rooms)
    if args.action == 'ips':
        homeservers = load_retrieved_servers(input_homeservers_file_path)
        retrieved_servers = load_retrieved_servers(retrieved_servers_file_path)
        homeservers.extend(retrieved_servers)
        input_homeservers = homeservers[args.start:args.end]
        retrieve_server_IPs(input_homeservers)