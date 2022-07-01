
import collections
import struct
from eu4_hacks import pidutil
from impulse.args import args


DEBUG = True
command = args.ArgumentParser(complete=True)


def SetDebug(debug):
  global DEBUG
  DEBUG = debug


def debug(str):
  if DEBUG:
    print(str)


def find_general_name(tok, proc, maps, lookback):
  print('scanning memory for general name')
  general = collections.namedtuple('General', ['region', 'address'])
  for region in maps:
    debug(f'scanning region {region.start_str} (len: {region.length})')
    for addr, data in proc.read(region.start, region.length, 1024, len(tok)):
      index = data.find(tok)
      if index != -1:
        debug(f'found string at index: {index + addr} ({index})')
        yield general(region, index+addr-lookback)


def find_potential_general_struct(tok, proc, maps, lookback):
  generals = [
    struct.pack('<Q', g.address) for g in find_general_name(
      tok, proc, maps, lookback)]
  print(f'rescanning memory for {len(generals)} general structures')
  for region in maps:
    debug(f'scanning region {region.start_str} (len: {region.length})')
    for addr, data in proc.read(region.start, region.length, 1024):
      for general in generals:
        index = data.find(general)
        if index != -1:
          print(f'found potential general at {hex(addr+index)}')
          yield addr + index


def find_general_struct(name, stats, proc, maps, lookback):
  for idx in find_potential_general_struct(name, proc, maps, lookback):
    for addr, data in proc.read(idx, 512, 512):
      index = data.find(stats)
      if index != -1:
        return addr + index
  return 0


def pack(fire, shock, maneuvre, siege):
  bytepack = (struct.pack('<L', int(siege)) +
              struct.pack('<L', int(shock)) +
              struct.pack('<L', int(fire))  +
              struct.pack('<L', int(maneuvre)))
  return bytepack


@command
def find(name:str,
         fire:int,
         shock:int,
         maneuvre:int,
         siege:int,
         lookback:int=0,
         dbg:bool=False):
  """Finds a general's stats memory address given name and stats."""
  SetDebug(dbg)
  bytepack = pack(fire, shock, maneuvre, siege)
  pid = pidutil.GetProcessByName('eu4')
  maps = list(pidutil.GetValidProcessMaps(pid))
  print(f'Got {len(maps)} valid regions')
  with pidutil.Ptrace(pid) as proc:
    namebytes = bytes(name, encoding='utf8')
    addr = find_general_struct(namebytes, bytepack, proc, maps, lookback)
    print(f'General {name} stats addr = {hex(addr)}')


@command
def change(name:str,
           fire:str,
           shock:str,
           maneuvre:str,
           siege:str,
           address:str=None,
           dbg:bool=False,
           lookback:int=0,
           maxout:bool=False):
  """Changes a general's stats given its name and current stats.
  
  Example: ./general change "Floris Twente" 2:5 0:1 1:4 0:999
  """
  SetDebug(dbg)
  debug(address)
  if maxout:
    fire = [fire, '9999']
    shock = [shock, '9999']
    maneuvre = [maneuvre, '9999']
    siege = [siege, '9999']
  else:
    fire = fire.split(':')
    shock = shock.split(':')
    maneuvre = maneuvre.split(':')
    siege = siege.split(':')
  bytepack = pack(fire[0], shock[0], maneuvre[0], siege[0])
  newpack = pack(fire[1], shock[1], maneuvre[1], siege[1])
  pid = pidutil.GetProcessByName('eu4')
  maps = list(pidutil.GetValidProcessMaps(pid))
  print(f'Got {len(maps)} valid regions')

  with pidutil.Ptrace(pid) as proc:
    if address is None:
      namebytes = bytes(name, encoding='utf8')
      addr = find_general_struct(namebytes, bytepack, proc, maps, lookback)
      print(f'General {name} stats addr = {hex(addr)}')
    else:
      addr = int(address, 16)

    if addr != 0:
      proc.write(addr, newpack)


def main():
  command.eval()
  
