#!/usr/bin/env python3

'''
Systemd service for managing wireguard interfaces and database.
'''

import os
import sys
import time
import logging
import logging.config
import psycopg2
import wgconsole

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

    if not os.path.exists(LOGF.rstrip('service.log')):
        os.makedirs(LOGF.rstrip('service.log'))

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
        state = wgconsole.WgState(connection)
        state.update()
        wgconsole.WgSetup(state, CONF).conf_setup()
        wgconsole.WgControl(state, CONF).update()
        state.update()
        connection.close()
        time.sleep(10)
