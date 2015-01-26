# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import abc
import datetime
import re
import socket
import time
import uuid

# KIPP0001 : create session
# KIPP0002 : succesful login
# KIPP0003 : failed login
# KIPP0004 : TTY log opened
# KIPP0005 : handle command
# KIPP0006 : handle unknown command
# KIPP0007 : file download
# KIPP0008 : INPUT
# KIPP0009 : SSH Version
# KIPP0010 : Terminal Size
# KIPP0011 : Connection Lost
# -- new event id's after this --
# KIPP0012 : SSH direct-tcpip fwd request

class Output(object):

    __metaclass__ = abc.ABCMeta

    def __init__(self, cfg):
        self.cfg = cfg
        self.sessions = {}
        self.ttylogs = {}
        self.re_sessionlog = re.compile(
            '.*HoneyPotTransport,([0-9]+),[0-9.]+$')
        if self.cfg.has_option('honeypot', 'sensor_name'):
            self.sensor = self.cfg.get('honeypot', 'sensor_name')
        else:
            self.sensor = socket.gethostname()

        self.start(cfg)

    # use logDispatch when the HoneypotTransport prefix is not available.
    # here you can explicitly set the sessionIds to tie the sessions together
    def logDispatch(self, sessionid, msg):
        if isinstance( msg, dict ):
            msg['sessionid'] = sessionid
            return self.emit( msg )
        elif isinstance( msg, str ):
            return self.emit( { 'message':msg, 'sessionid':sessionid } )

    @abc.abstractmethod
    def start():
        """Hook that can be used to set up connections in output plugins"""
        pass

    @abc.abstractmethod
    def stop():
        """Hook that can be used to close connections in output plugins"""
        pass

    # this is the main emit() hook that gets called by the the Twisted logging
    def emit(self, ev):
        # ignore stdout and stderr in output plugins
        if 'printed' in ev:
            return

        # ignore anything without eventid
        if not 'eventid' in ev:
            return

        # add ISO timestamp and sensor data
        if not ev['time']:
            ev['time'] = datetime.time.time()
        ev['timestamp'] = datetime.datetime.fromtimestamp(ev['time']).isoformat() + 'Z'
        ev['sensor'] = self.sensor

        # connection event is special. adds to list
        if ev['eventid'] == 'KIPP0001':
            sessionid = ev['sessionno']
            self.sessions[sessionid] = uuid.uuid4().hex
            self.handleLog( self.sessions[sessionid], ev )
            return

        # disconnection is special, add the tty log
        if ev['eventid'] == 'KIPP0011':
            # FIXME: file is read for each output plugin
            #f = file(self.ttylogs[session])
            #ev['ttylog'] = f.read(10485760)
            #f.close()
            pass

        # extract session id from the twisted log prefix
        # explicit sessionid (from logDispatch) overrides from 'system'
        if 'sessionid' in ev:
            sessionid = ev['sessionid']
        elif 'system' in ev:
            match = self.re_sessionlog.match(ev['system'])
            if not match:
                return
            sessionid = int(match.groups()[0])

        self.handleLog( self.sessions[sessionid], ev )
        # print "error calling handleLog for event  %s" % repr(ev)

    @abc.abstractmethod
    def handleLog( self, session, event ):
        """Handle a general event within the dblogger"""
        pass

# vim: set sw=4 et:
