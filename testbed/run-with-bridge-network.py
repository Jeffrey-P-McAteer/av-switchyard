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

number_of_taps = len(sys.argv[1:]) # 1 tap per sub-command
tap_names = [f'tap{i}-{BRIDGE_NAME}' for i in range(0, number_of_taps)]

if len(tap_names) < 1:
  print(f'Fatal: Refusing to setup networking for fewer than 1 subprocesses, pass at least one command!')
  sys.exit(1)

pretty_cmd('sudo', 'ip', 'link', 'add', 'name', BRIDGE_NAME, 'type', 'bridge')

for tap_name in tap_names:
  try:
    #pretty_cmd('sudo', 'ip', 'tuntap', 'add', 'dev', tap_name, 'mode', 'tap', 'user', f'{getpass.getuser()}')
    pretty_cmd('sudo', 'ip', 'tuntap', 'add', 'mode', 'tap', 'name', tap_name, 'user', f'{getpass.getuser()}')
    pretty_cmd('sudo', 'ip', 'link', 'set', tap_name, 'master', BRIDGE_NAME)
    pretty_cmd('sudo', 'ip', 'link', 'set', tap_name, 'up')
  except:
    traceback.print_exc()

pretty_cmd('sudo', 'ip', 'link', 'set', BRIDGE_NAME, 'up')

print(f'Network bridge {BRIDGE_NAME} with taps {",".join(tap_names)} setup')

try:
  subprocs = []
  for subcommand, tap_name in zip(sys.argv[1:], tap_names):
    subproc_env = dict(os.environ)
    subproc_env['VM_TAP_NAME'] = tap_name # each vm python script checks & creates network interface for this.
    subprocs.append(
      subprocess.Popen(['sh', '-c', subcommand], bufsize=1, text=True, env=subproc_env)
    )
  while len(subprocs) > 0:
    time.sleep(0.25)
    subprocs = [s for s in subprocs if s.poll() is None ]
  print('All subprocesses terminated!')
except:
  traceback.print_exc()

for tap_name in tap_names:
  try:
    pretty_cmd('sudo', 'ip', 'link', 'set', tap_name, 'nomaster')
    pretty_cmd('sudo', 'ip', 'link', 'set', tap_name, 'down')
    pretty_cmd('sudo', 'ip', 'link', 'delete', tap_name)
  except:
    traceback.print_exc()

pretty_cmd('sudo', 'ip', 'link', 'set', BRIDGE_NAME, 'down')
pretty_cmd('sudo', 'ip', 'link', 'delete', BRIDGE_NAME, 'type', 'bridge')


print(f'Network {BRIDGE_NAME} with taps {",".join(tap_names)}  taken down')
