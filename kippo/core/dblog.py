# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import re
import time
import abc

# KIPP-0001 : create session
# KIPP-0002 : succesful login
# KIPP-0003 : failed login
# KIPP-0004 : TTY log opened
# KIPP-0005 : handle command
# KIPP-0006 : handle unknown command
# KIPP-0007 : file download
# KIPP-0008 : INPUT
# KIPP-0009 : SSH Version
# KIPP-0010 : Terminal Size
# KIPP-0011 : Connection Lost

class DBLogger(object):
    def __init__(self, cfg):
        self.cfg = cfg
        self.sessions = {}
        self.ttylogs = {}
        self.re_sessionlog = re.compile(
            '.*HoneyPotTransport,([0-9]+),[0-9.]+$')

        self.events = { 
          'KIPP-0002': self.handleLoginSucceeded,
          'KIPP-0003': self.handleLoginFailed,
          'KIPP-0004': self.handleTTYLogOpened,
          'KIPP-0005': self.handleCommand,
          'KIPP-0006': self.handleUnknownCommand,
          'KIPP-0007': self.handleFileDownload,
          'KIPP-0008': self.handleInput,
          'KIPP-0009': self.handleClientVersion,
          'KIPP-0010': self.handleTerminalSize,
          'KIPP-0010': self._connectionLost,
        }

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
        pass

    def getSensor(self):
        if self.cfg.has_option('honeypot', 'sensor_name'):
            return self.cfg.get('honeypot', 'sensor_name')
        return None

    def nowUnix(self):
        """return the current UTC time as an UNIX timestamp"""
        return int(time.mktime(time.gmtime()[:-1] + (-1,)))

    def emit(self, ev):
        # ignore stdout and stderr in custom log observers
        if 'printed' in ev:
            return

        # DEBUG: REMOVE ME
        # print "emitting: %s" % repr( ev )

        # newstyle structured logging
        if 'eventid' in ev:
            if ev['eventid'] == 'KIPP-0001':
                sessionid = ev['sessionno']
                self.sessions[sessionid] = \
                    self.createSession(
                        ev['src_ip'], ev['src_port'], ev['dst_ip'], ev['dst_port'] )
                return

        # extract session id from the twisted log messages
        if 'system' in ev:
            match = self.re_sessionlog.match(ev['system'])
            if not match:
                return
            sessionid = int(match.groups()[0])
        elif 'sessionid' in ev:
            sessionid = ev['sessionid']

        if sessionid not in self.sessions.keys():
            return

        if 'eventid' in ev:
            id = ev['eventid']
            self.events[ev['eventid']]( self.sessions[sessionid], ev )
            return

    def _connectionLost(self, session, args):
        self.handleConnectionLost(session, args)
        if session in self.ttylogs:
            del self.ttylogs[session]
        for i in [x for x in self.sessions if self.sessions[x] == session]:
            del self.sessions[i]

    def ttylog(self, session):
        ttylog = None
        if session in self.ttylogs:
            f = file(self.ttylogs[session])
            ttylog = f.read(10485760)
            f.close()
        return ttylog

    # We have to return an unique ID
    @abc.abstractmethod
    def createSession(self, peerIP, peerPort, hostIP, hostPort):
        return 0

    # args has: logfile
    @abc.abstractmethod
    def handleTTYLogOpened(self, session, args):
        self.ttylogs[session] = args['logfile']

    # args is empty
    @abc.abstractmethod
    def handleConnectionLost(self, session, args):
        pass

    # args has: username, password
    @abc.abstractmethod
    def handleLoginFailed(self, session, args):
        pass

    # args has: username, password
    @abc.abstractmethod
    def handleLoginSucceeded(self, session, args):
        pass

    # args has: input
    @abc.abstractmethod
    def handleCommand(self, session, args):
        pass

    # args has: input
    @abc.abstractmethod
    def handleUnknownCommand(self, session, args):
        pass

    # args has: realm, input
    @abc.abstractmethod
    def handleInput(self, session, args):
        pass

    # args has: width, height
    @abc.abstractmethod
    def handleTerminalSize(self, session, args):
        pass

    # args has: version
    @abc.abstractmethod
    def handleClientVersion(self, session, args):
        pass

    # args has: url, outfile
    @abc.abstractmethod
    def handleFileDownload(self, session, args):
        pass

# vim: set sw=4 et:
