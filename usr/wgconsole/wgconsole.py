#!/usr/bin/env python3.10
'''
Systemd service for managing wireguard interfaces and database.
'''

import os
import re
import sys
import subprocess
import shlex
import time
import logging
import logging.config
import psycopg2

logger = logging.getLogger(__name__)

class WgControl:
    '''
    Class for controlling wireguard interfaces and databases.
    '''

    wgstate = {}

    def __init__(self, conf:str, conn) -> None:
        self.conf = os.fspath(conf)
        self.conn = conn

    def db_read(self, command:str) -> tuple:
        '''
        Read records from database table.
        '''
        with self.conn as conn:
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

    def db_write(self, command:str):
        '''
        Write records to database table.
        '''
        with self.conn as conn:
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

    @staticmethod
    def run_command(
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

    def state_interface(self):
        '''
        Update state information about interfaces.
        '''
        logger.debug('Execute state_interface!\n%s\n\n', '*'*80)
        self.wgstate = {}
        records = self.db_read(
            'SELECT name, state\n'
            'FROM wgconsole_interface;'
        )
        for record in records:
            name, state = record
            wgshow = self.run_command(
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
                self.db_write(
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
            'End of state_interface executing, wgstate variable contains:\n%s\n\n',
            self.wgstate
        )

    def state_peer(self):
        '''
        Update state information about peers.
        '''
        logger.debug('Execute state_peer!\n%s\n\n', '*'*80)
        records = self.db_read(
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
                    self.db_write(
                        'UPDATE wgconsole_peer\n'
                        f'SET state = \'{peer_state}\'\n'
                        f'WHERE public_key = \'{peer}\';'
                    )
        for peer in db_peers:
            if peer not in all_active_peers and db_peers[peer] != '':
                self.db_write(
                    'UPDATE wgconsole_peer\n'
                    f'SET state = \'\'\n'
                    f'WHERE public_key = \'{peer}\';'
                )
        logger.debug('End of executing state_peer!\n\n')

    def conf_setup(self):
        '''
        Update interface settings in db according to .conf file
        '''
        logger.debug('Execute conf_setup!\n%s\n\n', '*'*80)
        records = self.db_read(
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
                if conf['Address'] != address:
                    self.db_write(
                        'UPDATE wgconsole_interface\n'
                        f'SET address = \'{conf["Address"]}\'\n'
                        f'WHERE name = \'{name}\';'
                    )
            else:
                logger.error(
                    'No Address record in %s.conf file\n',
                    name
                )
            if 'ListenPort' in conf:
                try:
                    if int(conf['ListenPort']) != port:
                        self.db_write(
                            'UPDATE wgconsole_interface\n'
                            f'SET port = \'{conf["ListenPort"]}\'\n'
                            f'WHERE name = \'{name}\';'
                        )
                except ValueError:
                    logger.error(
                        'ListenPort record value in %s.conf file not'
                        ' integer\n',
                        name
                    )
            else:
                logger.error(
                    'No ListenPort record in %s.conf file\n',
                    name
                )
            if 'PrivateKey' in conf:
                private_key = conf['PrivateKey']
                pubkey = self.run_command(
                    'wg pubkey',
                    input_str=f'{private_key}'
                )
                pubkey = pubkey.rstrip('\n')
                if pubkey != public_key:
                    self.db_write(
                        'UPDATE wgconsole_interface\n'
                        f'SET public_key = \'{pubkey}\'\n'
                        f'WHERE name = \'{name}\';'
                    )
            else:
                logger.error(
                    'No PrivateKey record in %s.conf file\n',
                    name
                )
        logger.debug('End of executing conf_setup!\n\n')

    def update(self):
        '''
        Update interfaces.
        '''
        logger.debug('Execute update!\n%s\n\n', '*'*80)
        self.state_interface()
        self.state_peer()
        self.conf_setup()
        interface_records = self.db_read(
            'SELECT name, status, state\n'
            'FROM wgconsole_interface;'
        )
        for record in interface_records:
            name, status, state = record
            if state is False and status is True:
                self.run_command(
                    f'wg-quick up {self.conf}/{name}.conf',
                    logerr=True,
                )
            if state is True and status is False:
                self.run_command(
                    f'wg-quick down {self.conf}/{name}.conf',
                    logerr=True,
                )
            if status is False:
                continue
            peer_records = self.db_read(
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
                    self.run_command(
                        f'wg set {name} peer {public_key} '
                        f'allowed-ips {allowed_ips}'
                    )
                    self.run_command(
                        f'ip -4 route add {allowed_ips} dev {name}'
                    )
                if public_key in peers and peer_status is False:
                    self.run_command(
                        f'wg set {name} peer {public_key} remove'
                    )
                    self.run_command(
                        f'ip -4 route del {allowed_ips} dev {name}'
                    )
                if public_key in peers:
                    peers.remove(public_key)
            for public_key in peers:
                self.run_command(
                    f'wg set {name} peer {public_key} remove'
                )
                allowed_ips = self.wgstate[name]['peers'][public_key]\
                    ['allowed ips']
                self.run_command(
                    f'ip -4 route del {allowed_ips} dev {name}'
                )
        self.state_interface()
        self.state_peer()
        logger.debug('End of executing update!\n\n')



if __name__ == '__main__':

    sys.path.append(os.path.abspath('/etc/wgconsole'))
    import config

    DBNAME = config.DBNAME
    DBUSER = config.DBUSER
    DBPASS = config.DBPASS
    DBHOST = config.DBHOST
    DBPORT = config.DBPORT

    CONF = os.path.abspath('/etc/wgconsole/conf.d')
    LOGF = os.path.abspath('/var/wgconsole/service.log')

    logging.config.dictConfig({
        'version':1,
        'formatters':{
            'message':{
                'format':'%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                'datefmt':'%Y.%m.%d %H:%M:%S',
            },
        },
        'handlers':{
            'console':{
                'class':'logging.StreamHandler',
                'formatter':'message',
            },
            'file':{
                'class':'logging.handlers.RotatingFileHandler',
                'formatter':'message',
                'filename':f'{LOGF}',
                'maxBytes': 1024*1024*1,
                'backupCount': 3,
            },
        },
        'root':{
            'level':'ERROR',
            'handlers':['file',],
        },
        'disable_existing_loggers':False,
    })
    logger = logging.getLogger('wgconsole')

    # Change process name
    if os.uname()[0] == 'Linux':
        import ctypes
        libc = ctypes.cdll.LoadLibrary('libc.so.6')
        libc.prctl(15, b'wgconsole', None, None, None)

    while True:
        try:
            connection = psycopg2.connect(
                dbname = DBNAME,
                user = DBUSER,
                password = DBPASS,
                host = DBHOST,
                port = DBPORT
            )
        except psycopg2.OperationalError:
            logger.error('Error connecting to database\n')
            time.sleep(5)
            continue
        wgctrl = WgControl(CONF, connection)
        wgctrl.update()
        connection.close()
        time.sleep(10)
