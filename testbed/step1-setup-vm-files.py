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

def die(msg):
  print(msg)
  sys.exit(1)

def glob_for_nonempty_files(root_dir, glob_str):
  '''We commonly check for "did the user download 'tool-*-.extension", and we don't want to accept 0-byte files as "yes the user did it" '''
  results = []
  for file in glob.glob(glob_str, root_dir=root_dir, recursive=True):
    if not str(file).startswith(root_dir):
      file = os.path.join(root_dir, file)

    if os.path.isfile(file) and os.path.getsize(file) > 0:
      results.append(file)

    if not os.path.isfile(file):
      print(f'Warning: {file} is not a file!')
    if os.path.isfile(file) and os.path.getsize(file) < 1:
      print(f'Warning: {file} is an empty (0-byte) file. Please ensure your download completed?')
  return results

def glob_for_nonempty_file_fatal(root_dir, glob_str, pre_die_msg):
  results = glob_for_nonempty_files(root_dir, glob_str)
  if len(results) <= 0:
    print(pre_die_msg.strip())
    die(f'Found 0 files matching the above criteria, please create/fetch the file!')
  if len(results) > 1:
    print(pre_die_msg.strip())
    die(f'Found more than one file matching the above criteria, please delete duplicates until the desired one remains!\nDiscovered matching files: {results}')
  # Safety: the above checks prove len(results) == 0
  return results[0]

def pretty_cmd(*cmd, **kwargs):
  debug_cmd_txt = shlex.join(cmd)
  print(f'> {debug_cmd_txt}')
  subprocess.run(list(cmd), **kwargs)

testbed_folder = os.path.dirname(os.path.realpath(__file__))

req_bins = [
  'qemu-system-x86_64', 'qemu-img'
]

for b in req_bins:
  if shutil.which(b) is None:
    die(f'Cannot find required binary {b}, please install and ensure containing folder is on your $PATH')

vm_data_folder = os.path.join(testbed_folder, 'vm-data')
os.makedirs(vm_data_folder, exist_ok=True)

# Setup step 1: Do we have a windows 10 iso image to do initial install with?
# If not, instruct user to grab one (automated processes change every 6 months -_-)
install_iso = glob_for_nonempty_file_fatal(
  vm_data_folder, '*.iso',
  f'''
Please download a windows installer .iso file from a site such as
 - https://www.microsoft.com/en-us/software-download/windows10ISO
and place it under the folder {vm_data_folder}
'''
)

# Step step 2: have a .qcow2 for the VM, we can do this ourselves with qemu-img
vm_qcow2s = glob_for_nonempty_files(vm_data_folder, '*.qcow2')
if len(vm_qcow2s) > 1:
  die(f'We have found 2 or more VM hard drive files, please delete the one you do not plan to use! Discovered qcow2 files: {vm_qcow2s}')
if len(vm_qcow2s) < 1:
  qemu_img_exe = shutil.which('qemu-img')
  vm_qcow2 = os.path.join(vm_data_folder, 'Windows-Test-VM.qcow2') # Assignment: Default qcow2 name
  pretty_cmd(qemu_img_exe, 'create', '-f', 'qcow2', vm_qcow2, '120G')

# Safety: Above checks ensure we should have at least one .qcow2 file.
vm_qcow2s = glob_for_nonempty_files(vm_data_folder, '*.qcow2')
if len(vm_qcow2s) < 1:
  die(f'Failed to find any .qcow2 files under {vm_data_folder}, please inspect command output above for the issue and grab a developer.')
vm_qcow2 = vm_qcow2s[0]




