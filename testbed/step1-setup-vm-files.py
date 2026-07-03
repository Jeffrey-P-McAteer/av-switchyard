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

def ask_user_yn_question(question_str):
  while True:
    yn = input(question_str)
    yn = yn.strip().lowercase()
    if yn == 'y' or yn == 'yes':
      return True
    if yn == 'n' or yn == 'no'
      return True

    print(f'Unknown response "{yn}", please answer with one of y/yes/n/no (ctrl+c to terminate this script)')


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
  pretty_cmd(
    qemu_img_exe, 'create', '-f', 'qcow2', vm_qcow2, '120G',
    cwd=vm_data_folder
  )

# Safety: Above checks ensure we should have at least one .qcow2 file.
vm_qcow2s = glob_for_nonempty_files(vm_data_folder, '*.qcow2')
if len(vm_qcow2s) < 1:
  die(f'Failed to find any .qcow2 files under {vm_data_folder}, please inspect command output above for the issue and grab a developer.')
vm_qcow2 = vm_qcow2s[0]

# Grab our required QEMU details from the host
qemu_system_exe = shutil.which('qemu-system-x86_64')
ovmf_code_fd_file = os.environ.get('OVMF_CODE_FILE', None)
canidate_firmware_names = [
  'OVMF_CODE.fd', 'OVMF_CODE.4m.fd'
]
if ovmf_code_fd_file is None:
  # Glob /usr/share for a few file names, using the first
  for canidate_firmware_name in canidate_firmware_names:
    found_fd_files = glob_for_nonempty_files('/usr/share', f'**/{canidate_firmware_name}')
    if len(found_fd_files) > 0:
      ovmf_code_fd_file = found_fd_files[0]
      break
if ovmf_code_fd_file is None or not os.path.exists(ovmf_code_fd_file):
  die(f'''
Cannot find a copy of OVMF_CODE, please ensure edk2 or a similar package is installed.
By default we scan /usr/share for any of the following file names: {canidate_firmware_names}
You may manually specify a location to the file by assigning the environment variable OVMF_CODE_FILE
Current value OVMF_CODE_FILE={ovmf_code_fd_file}
''')


vm_is_installed_flag_file = os.path.join(vm_data_folder, 'FLAG-vm-install-completed.txt')
if not os.path.exists(vm_is_installed_flag_file):
  print(f'VM needs to be installed, launching install instance.')
  print(f'Please install the OS, then close the VM once you are done and return here.')

  pretty_cmd(
    qemu_system_exe,
      '-enable-kvm'
      '-m', '8192',
      '-smp', '4',
      '-cpu', 'host',
      '-machine', 'q35',
      '-bios', f'{ovmf_code_fd_file}',
      '-drive', f'file={vm_qcow2},format=qcow2,if=ide',
      '-cdrom', f'{install_iso}',
      '-netdev', 'user,id=net0',
      '-device', 'e1000,netdev=net0',
      '-vga', 'std',
      '-display', 'gtk',
  cwd=vm_data_folder)

  os_was_installed = ask_user_yn_question(f'Did OS install complete to your satisfaction?')
  if not os_was_installed:
    die(f'Exiting because OS was not installed, re-run this script to launch VM in install mode again when you are ready.')

  with open(vm_is_installed_flag_file, 'w') as fd:
    fd.write(f'User completed install at {datetime.datetime.now()}')

if not os.path.exists(vm_is_installed_flag_file):
  die(f'Exiting because OS was not installed, re-run this script to launch VM in install mode again when you are ready.')

print(f'OS install is complete, we see the flag file {vm_is_installed_flag_file}')
