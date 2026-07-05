#!/usr/bin/env -S uv run --script
#
# /// script
# requires-python = ">=3.12"
# dependencies = [
#
# ]
# ///


import os
import sys
import shutil
import glob
import shlex
import subprocess
import datetime
import tempfile
import pathlib
import traceback
import getpass
import time

def pretty_cmd(*cmd, **kwargs):
  debug_cmd_txt = shlex.join(cmd)
  print(f'> {debug_cmd_txt}')
  subprocess.run(list(cmd), **kwargs)

testbed_folder = os.path.dirname(os.path.realpath(__file__))
av_bridge_name_txt_file = os.path.join(testbed_folder, 'av-bridge-network-name.txt')

with open(av_bridge_name_txt_file, 'r') as fd:
  BRIDGE_NAME = fd.read().strip()
TAP_NAME = f'tap-{BRIDGE_NAME}'

pretty_cmd('sudo', 'ip', 'tuntap', 'add', 'dev', TAP_NAME, 'mode', 'tap', 'user', f'{getpass.getuser()}')
pretty_cmd('sudo', 'ip', 'link', 'set', TAP_NAME, 'master', BRIDGE_NAME)
pretty_cmd('sudo', 'ip', 'link', 'set', TAP_NAME, 'up')
pretty_cmd('sudo', 'ip', 'link', 'set', BRIDGE_NAME, 'up')

print(f'Network {BRIDGE_NAME} / tap {TAP_NAME} setup')

try:
  subprocs = []
  for arg in sys.argv[1:]:
    subprocs.append(
      subprocess.Popen(['sh', '-c', arg], bufsize=1, text=True)
    )
  while len(subprocs) > 0:
    time.sleep(0.25)
    subprocs = [s for s in subprocs if s.poll() is None ]
  print('All subprocesses terminated!')
except:
  traceback.print_exc()

pretty_cmd('sudo', 'ip', 'link', 'set', TAP_NAME, 'nomaster')
pretty_cmd('sudo', 'ip', 'link', 'set', TAP_NAME, 'down')
pretty_cmd('sudo', 'ip', 'link', 'delete', TAP_NAME)
pretty_cmd('sudo', 'ip', 'link', 'set', BRIDGE_NAME, 'down')
pretty_cmd('sudo', 'ip', 'link', 'delete', BRIDGE_NAME, 'type', 'bridge')


print(f'Network {BRIDGE_NAME} / tap {TAP_NAME} taken down')
