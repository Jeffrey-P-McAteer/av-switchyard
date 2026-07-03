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
import subprocess
import traceback
import time

testbed_folder = os.path.dirname(os.path.realpath(__file__))
vm_data_folder = os.path.join(testbed_folder, 'vm-data')

test_vm_disk_image = os.path.join(vm_data_folder, 'vm-test-artifact-disk.img')
mount_dir = sys.argv[1]

loop_dev = subprocess.check_output([
    'sudo', 'losetup', '--find', '--show', str(test_vm_disk_image)
]).decode().strip()
expected_partition_dev = loop_dev+'p1'

try:
  time.sleep(1.5)

  subprocess.run([
    'sudo', 'mount', '-o', f'uid={os.getuid()},gid={os.getgid()}', expected_partition_dev, mount_dir
  ])

  print(f'{expected_partition_dev} has been mounted to {mount_dir}')

  input('Press enter to continue...')

except Exception:
  traceback.print_exc()
  subprocess.run(['sudo', 'umount', mount_dir], check=False)
  subprocess.run(['sudo', 'losetup', '-d', loop_dev], check=False)
finally:
  subprocess.run(['sudo', 'umount', mount_dir], check=False)
  subprocess.run(['sudo', 'losetup', '-d', loop_dev], check=False)
