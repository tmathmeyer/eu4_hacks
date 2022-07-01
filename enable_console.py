
import os

from eu4_hacks import pidutil

from impulse.args import args
from impulse.util import resources


COMMAND = args.ArgumentParser(complete=True)

# How to update this shit:
# find the string "Command not available in multiplayer or ironman mode."
# find it's address, example: 0x027d1b78
# find xref address, example: 0x02473924
# the function should be "CConsoleCmdManager::Execute(CArray<CString> const&)"
# check the graph view in cutter - there should be a block with a test and a je
# save those two, example: test@0x02473914 jump@0x0247393c
# now there's one more segfault address - it's wayyyy near the bottom of the
# function graph, and has a comment "1337". there's a block before it that
# conditionally skips over it, so we'll have to take that jump.
# example: test@0x02473b2a, jump@0x02473b39
# Now for each of these addresses, add a block to "skip_ironman_checks.gdb":
# break *{test_addr}
#   commands
#   silent
#   jump *{jump_addr}
#   continue
# end

@COMMAND
def enable():
  pid = pidutil.GetProcessByName('eu4')
  if pid:
    print(f'found eu4 pid: {pid}')
    skip_ironman_checks = resources.Resources.Get(
      'eu4_hacks/skip_ironman_checks.gdb')
    os.system(f'gdb eu4 {pid} -x {skip_ironman_checks}')
  else:
    print('eu4 not running!')



def main():
  COMMAND.eval()

