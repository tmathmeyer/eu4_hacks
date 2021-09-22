

import collections
from eu4_hacks import pidutil
from impulse.args import args


COMMAND = args.ArgumentParser(complete=True)
JUMP_PATTERN_PRECURSOR = b'\x74'
#JUMP_PATTERN_A = b'\xc6\x44\x24\x28\x00\x41\xb8\x35\x00\x00\x00'
JUMP_PATTERN_B = b'\xc7\x04\x25\x00\x00\x00\x00\x39\x05\x00\x00'
JUMP_PATTERN_A = b'\x7E\x00\x00\x00'

DEBUG = True


def SetDebug(debug):
  global DEBUG
  DEBUG = debug


def debug(str):
  if DEBUG:
    print(str)


def find_pattern_offsets(proc, maps):
  print('scanning memory for jump offsets')
  Offset = collections.namedtuple('Offset', ['region', 'address'])
  for region in maps:
    debug(f'scanning region {region.start_str} (len: {region.length})')
    for addr, data in proc.read(region.start, region.length, 1024, 13):
      index = data.find(JUMP_PATTERN_A)
      if index > 1 and data[index-2] == JUMP_PATTERN_PRECURSOR:
        yield Offset(region, index+addr-2)

      index = data.find(JUMP_PATTERN_B)
      if index > 1 and data[index-2] == JUMP_PATTERN_PRECURSOR:
        yield Offset(region, index+addr-2)


@COMMAND
def enable(dbg:bool=False):
  """Enables console on eu4 ironman."""
  SetDebug(dbg)

  pid = pidutil.GetProcessByName('eu4')
  maps = list(pidutil.GetValidProcessMaps(pid))
  print(f'Got {len(maps)} valid regions')
  with pidutil.Ptrace(pid) as proc:
    print(list(find_pattern_offsets(proc, maps)))


def main():
  COMMAND.eval()