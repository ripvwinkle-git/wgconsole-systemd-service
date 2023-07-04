#!/usr/bin/env python3

'''
Systemd service for managing wireguard interfaces and database.
'''

import os
import re
import subprocess
import shlex
import logging
import ipaddress
import psycopg2

logger = logging.getLogger(__name__)

def db_read(
    connection, # psycopg2 database connection object
    command:str
) -> tuple:
    '''
    Read records from PostgreSQL database table.
    '''
    with connection as conn:
        with conn.cursor() as curr:
            try:
                curr.execute(command)
                records = tuple(curr)
                logger.debug(
                    'Reading records from database'
                    '\nCommand:\n%s\n'
                    'Result:\n%s\n\n',
                    command, records
                )
                return records
            except psycopg2.ProgrammingError as exception:
                logger.error(
                    'Error reading from database'
                    '\nCommand:\n%s\n%s\n\n',
                    command, exception
                )
                return tuple()

def db_write(
    connection, # psycopg2 database connection object
    command:str
) -> None:
    '''
    Write records to PostgreSQL database table.
    '''
    with connection as conn:
        with conn.cursor() as curw:
            try:
                curw.execute(command)
                logger.debug(
                    'Writing records to database'
                    '\nCommand:\n%s\n\n', command
                )
            except psycopg2.ProgrammingError as exception:
                logger.error(
                    'Error writing to database'
                    '\nCommand:\n%s\n%s\n\n',
                    command, exception
                )

def run_cmmd(
    command: str,
    input_str: str = None,
    logerr: bool = False
) -> str:
    '''
    Subprocess module wrapper
    '''
    try:
        process = subprocess.run(
            shlex.split(command),
            input = input_str,
            capture_output=True,
            encoding='UTF-8',
            timeout=5,
            check=True
        )
        logger.debug(
            'Process complited'
            '\nCommand:\n%s\nstdout:\n%s\n\n',
            command, process.stdout
        )
        if process.stdout:
            return process.stdout
        return False
    except FileNotFoundError as exception:
        logger.debug(
            'Process failed, executable could not be found'
            '\nCommand:\n%s\n%s\n\n',
            command, exception
        )
        return False
    except subprocess.CalledProcessError as exception:
        if logerr:
            logger.error(
                'Process failed because did not return a successful '
                'return code'
                '\nCommand:\n%s\nReturned: %s\n%s\n\n',
                command, exception.returncode, exception.stderr
            )
        return False
    except subprocess.TimeoutExpired as exception:
        logger.error(
            'Process timed out'
            '\nCommand:\n%s\n%s\n\n',
            command, exception
        )
        return False

class WgState:
    '''
    Class for retrieve actual interface state and update it in db. 
    '''

    wgstate = {}

    def __init__(self, conn) -> None:
        self.conn = conn

    def update_interface(self) -> None:
        '''
        Update state information about interfaces.
        '''
        logger.debug('Execute WgState.update_interface\n%s\n\n', '*'*80)
        self.wgstate = {}
        records = db_read(
            self.conn,
            'SELECT name, state\n'
            'FROM wgconsole_interface;'
        )
        for record in records:
            name, state = record
            wgshow = run_cmmd(
                f'wg show {name}'
            )
            if wgshow:
                showed_state = True
                peers = {}
                wgshow_peers = re.findall(
                    r'(?:peer: )(.+)',
                    wgshow
                )
                for peer in wgshow_peers:
                    prop_in_wgshow = re.search(
                        fr'(?s)(?:{re.escape(peer)}\s+)'
                        r'(?P<props>.+?)(?:peer|\Z)',
                        wgshow
                    )
                    peer_prop = {
                        f'{prop}':f'{val}' for prop, val
                        in re.findall(
                        r'(?:\s*)(\w.+): (.+)(?:\n)',
                        prop_in_wgshow['props'],
                    )}
                    peers.update({peer: peer_prop})
            if not wgshow:
                showed_state = False
                peers = {}
            if showed_state != state:
                db_write(
                    self.conn,
                    'UPDATE wgconsole_interface\n'
                    f'SET state = \'{showed_state}\'\n'
                    f'WHERE name = \'{name}\';'
                )
            self.wgstate.update({name: {
                'state':showed_state,
                'peers':peers,
                }}
            )
        logger.debug(
            'End of WgState.update_interface executing, '
            'wgstate variable contains:\n%s\n\n',
            self.wgstate
        )

    def update_peer(self) -> None:
        '''
        Update state information about peers.
        '''
        logger.debug('Execute WgState.update_peer\n%s\n\n', '*'*80)
        records = db_read(
            self.conn,
            'SELECT public_key, state\n'
            'FROM wgconsole_peer;'
        )
        db_peers = dict(records)
        all_active_peers = set({})
        for interface in self.wgstate.values():
            peers = interface['peers']
            active_peers = {peer for peer in peers if peer in db_peers}
            all_active_peers.update(active_peers)
            for peer in active_peers:
                peer_state = '\n'.join([
                    prop + ': ' + peers[peer][prop] for prop
                    in peers[peer]
                    ])
                if peer_state != db_peers[peer]:
                    db_write(
                        self.conn,
                        'UPDATE wgconsole_peer\n'
                        f'SET state = \'{peer_state}\'\n'
                        f'WHERE public_key = \'{peer}\';'
                    )
        for peer in db_peers:
            if peer not in all_active_peers and db_peers[peer] != '':
                db_write(
                    self.conn,
                    'UPDATE wgconsole_peer\n'
                    f'SET state = \'\'\n'
                    f'WHERE public_key = \'{peer}\';'
                )
        logger.debug('End of executing WgState.update_peer\n\n')

    def update(self) -> None:
        '''
        Update state information about interfaces and peers.
        '''
        self.update_interface()
        self.update_peer()

class WgSetup:
    '''
    Class for updating interface settings in db according to .conf file
    '''

    def __init__(self, state:WgState, conf:str) -> None:
        self.wgstate = state.wgstate
        self.conf = os.fspath(conf)
        self.conn = state.conn

    def conf_setup(self) -> None:
        '''
        Update interface settings in db according to .conf file
        '''
        logger.debug('Execute WgSetup.conf_setup\n%s\n\n', '*'*80)
        records = db_read(
            self.conn,
            'SELECT name, address, port, public_key\n'
            'FROM wgconsole_interface;'
        )
        records = (record for record in records
            if self.wgstate[record[0]]['state'] is False
        )
        for record in records:
            name, address, port, public_key = record
            try:
                with open(
                    f'{self.conf}/{name}.conf',
                    mode='r', buffering=1,
                    encoding='utf-8',
                    errors='strict',
                    newline=None,
                    closefd=True,
                    opener=None
                ) as file:
                    conf = dict(
                        line.removesuffix('\n').split(' = ')
                        for line in file.readlines()
                        if ' = ' in line
                    )
            except FileNotFoundError:
                logger.error(
                        'No .conf file: %s',
                        f'{self.conf}/{name}.conf\n'
                    )
                continue
            if 'Address' in conf:
                try:
                    conf_address = str(ipaddress.ip_network(conf['Address']))
                    if conf_address != address:
                        db_write(
                        self.conn,
                        'UPDATE wgconsole_interface\n'
                        f'SET address = \'{conf["Address"]}\'\n'
                        f'WHERE name = \'{name}\';'
                        )
                except ValueError:
                    logger.error(
                    'Address record in %s.conf is not correct\n',
                    name
                    )
            else:
                logger.error(
                    'No Address record in %s.conf\n',
                    name
                )
            if 'ListenPort' in conf:
                try:
                    conf_port = int(conf['ListenPort'])
                    if 0 <= conf_port <= 65536:
                        if conf_port != port:
                            db_write(
                                self.conn,
                                'UPDATE wgconsole_interface\n'
                                f'SET port = \'{conf["ListenPort"]}\'\n'
                                f'WHERE name = \'{name}\';'
                            )
                    else:
                        logger.error(
                            'ListenPort record in %s.conf out of range\n',
                            name
                        )
                except ValueError:
                    logger.error(
                        'ListenPort record in %s.conf not integer\n',
                        name
                    )
            else:
                logger.error(
                    'No ListenPort record in %s.conf\n',
                    name
                )
            if 'PrivateKey' in conf:
                private_key = conf['PrivateKey']
                pubkey = run_cmmd(
                    'wg pubkey',
                    input_str = f'{private_key}',
                    logerr = True
                )
                if pubkey is not False:
                    pubkey = pubkey.rstrip('\n')
                    if pubkey != public_key:
                        db_write(
                            self.conn,
                            'UPDATE wgconsole_interface\n'
                            f'SET public_key = \'{pubkey}\'\n'
                            f'WHERE name = \'{name}\';'
                        )
            else:
                logger.error(
                    'No PrivateKey record in %s.conf\n',
                    name
                )
        logger.debug('End of executing WgSetup.conf_setup\n\n')

class WgControl:
    '''
    Class for managing Wireguard interfaces.
    '''

    def __init__(self, state:WgState, conf:str) -> None:
        self.wgstate = state.wgstate
        self.conn = state.conn
        self.conf = os.fspath(conf)

    def update(self) -> None:
        '''
        Update Wireguard interfaces according state and status in db.
        '''
        logger.debug('Execute WgControl.update\n%s\n\n', '*'*80)
        interface_records = db_read(
            self.conn,
            'SELECT name, status, state\n'
            'FROM wgconsole_interface;'
        )
        for record in interface_records:
            name, status, state = record
            if state is False and status is True:
                run_cmmd(
                    f'wg-quick up {self.conf}/{name}.conf',
                    logerr=True,
                )
            if state is True and status is False:
                run_cmmd(
                    f'wg-quick down {self.conf}/{name}.conf',
                    logerr=True,
                )
            if status is False:
                continue
            peer_records = db_read(
                self.conn,
                'SELECT public_key, allowed_ips, status\n'
                'FROM wgconsole_peer\n'
                f'WHERE interface_id = \'{name}\';'
            )
            peers = list(self.wgstate[name]['peers'])
            logger.debug(
                'List of peers from wgstate:\n%s\n',
                peers
            )
            for record in peer_records:
                public_key, allowed_ips, peer_status = record
                if public_key not in peers and peer_status is True:
                    run_cmmd(
                        f'wg set {name} peer {public_key} '
                        f'allowed-ips {allowed_ips}'
                    )
                    run_cmmd(
                        f'ip -4 route add {allowed_ips} dev {name}'
                    )
                if public_key in peers and peer_status is False:
                    run_cmmd(
                        f'wg set {name} peer {public_key} remove'
                    )
                    run_cmmd(
                        f'ip -4 route del {allowed_ips} dev {name}'
                    )
                if public_key in peers:
                    peers.remove(public_key)
            for public_key in peers:
                run_cmmd(
                    f'wg set {name} peer {public_key} remove'
                )
                allowed_ips = self.wgstate[name]['peers'][public_key]\
                    ['allowed ips']
                run_cmmd(
                    f'ip -4 route del {allowed_ips} dev {name}'
                )
        logger.debug('End of executing WgControl.update\n\n')
