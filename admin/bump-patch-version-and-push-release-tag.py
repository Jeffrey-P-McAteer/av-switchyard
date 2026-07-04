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
import re
import shlex

def die(msg):
  print(msg)
  sys.exit(1)

def pretty_cmd(*cmd, **kwargs):
  debug_cmd_txt = shlex.join(cmd)
  print(f'> {debug_cmd_txt}')
  subprocess.run(list(cmd), **kwargs)

def increment_version(version):
    # Match prefix + last number
    match = re.match(r"^(.*?)(\d+)$", version)
    if not match:
        raise ValueError(f'Invalid version format: {version}')

    prefix, last_num = match.groups()
    incremented = str(int(last_num) + 1)

    return prefix + incremented

def ask_user_yn_question(question_str):
  while True:
    yn = input(question_str)
    yn = yn.strip().lower()
    if yn == 'y' or yn == 'yes':
      return True
    if yn == 'n' or yn == 'no':
      return True

    print(f'Unknown response "{yn}", please answer with one of y/yes/n/no (ctrl+c to terminate this script)')

def is_git_repo_clean():
    try:
        result = subprocess.run(
            ['git', 'status', '--porcelain'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
    except subprocess.CalledProcessError as e:
        print('ERROR: Not a git repository or git command failed.', file=sys.stderr)
        print(e.stderr, file=sys.stderr)
        return False

    output = result.stdout.strip()
    return len(output) <= 0

repo_root = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
version_txt_file = os.path.join(repo_root, 'av-switchyard', 'version.txt')

if not os.path.exists(version_txt_file):
  die(f'FATAL: Please create the version text file {version_txt_file} before running this script!')

with open(version_txt_file, 'r') as fd:
  version_string = fd.read().strip()

if not version_string.startswith('v'):
  print(f'WARNING current version string does not begin with "v" - no CI pipeline will be run!')
  print(f'Read version = "{version_string}"')
  if not ask_user_yn_question('Continue despite the unexpected version format? '):
    die(f'Exiting because {version_txt_file} has unexpected format which user does not want to use. Please change to begin with "v"')

print(f'Existing version = {version_string}')

if not is_git_repo_clean():
  die(f'Refusing to write changes and create tag, git repository is dirty! Please commit changes and retry.')

new_version = increment_version(version_string)
print(f'New version = {new_version}')

with open(version_txt_file, 'w') as fd:
  fd.write(new_version)

# Commit changes
pretty_cmd('git', 'add', version_txt_file)
pretty_cmd('git', 'commit', '-m', f'Version update to {new_version}')
pretty_cmd('git', 'push')

# Create and push tag to 'origin' (TODO abstract out and find the first/last-used remote? Likely too much work to matter)
pretty_cmd('git', 'tag', new_version)
pretty_cmd('git', 'push', 'origin', new_version)
