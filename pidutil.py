
import collections
import ctypes
import os
import subprocess


PTRACE_ATTACH = 16
PTRACE_DETACH = 17


def Run(command):
  return subprocess.run(command,
                        encoding='utf-8',
                        shell=True,
                        stderr=subprocess.PIPE,
                        stdout=subprocess.PIPE)


def Ensure(command):
  r = Run(command)
  if r.returncode:
    raise ValueError(command)
  return r.stdout


def GetProcessByName(name:str) -> int:
  for line in Ensure('ps -u ted').split('\n')[1:]:
    line = line.strip()
    if not line:
      continue
    pid, _, _, *cmd = line.split()
    if cmd[0] == name:
      return int(pid)


def GetValidProcessMaps(pid:int) -> []:
  mmap = collections.namedtuple('Map', ['start', 'length', 'start_str'])
  for line in Ensure(f'cat /proc/{pid}/maps').split('\n'):
    line = line.strip()
    if not line:
      continue
    region, perms, offset, dec, inode, *pathname = line.split()
    if inode != '0' or (pathname and pathname[0] != '[heap]'):
      continue
    if perms[0] != 'r' or perms[1] != 'w':
      continue
    start, end = region.split('-')
    yield mmap(int(start, 16), int(end, 16) - int(start, 16), start)


class Ptrace(object):
  __slots__ = ['_pid', '_libc', '_procmem']
  
  def __init__(self, pid:int):
    self._libc = ctypes.CDLL('/usr/lib/libc.so.6')
    self._pid = pid
    self._procmem = None

  def read(self, address, length, chunk_size, overlap=0):
    while length:
      readback = min(chunk_size, length)
      yield address, os.pread(self._procmem, readback, address)
      if readback > overlap:
        readback -= overlap
      address += readback
      length -= readback

  def write(self, address, string):
    os.pwrite(self._procmem, string, address)

  def __enter__(self):
    try:
      self._libc.ptrace(PTRACE_ATTACH, self._pid, None, None)
      stat = os.waitpid(self._pid, 0)
      if not os.WIFSTOPPED(stat[1]):
        raise ValuError('Cant attach to pid')

      if os.WSTOPSIG(stat[1]) != 19:
        raise ValueError('Cant attach to pid')

      self._procmem = os.open(f'/proc/{self._pid}/mem', os.O_RDWR)
    except Exception as e:
      self.__exit__()
      raise

    return self

  def __exit__(self, *args, **kwargs):
    if self._procmem:
      os.close(self._procmem)
    self._libc.ptrace(PTRACE_DETACH, self._pid, None, None)