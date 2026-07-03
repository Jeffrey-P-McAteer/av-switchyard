#!/usr/bin/env -S uv run --script
#
# /// script
# requires-python = ">=3.12"
# dependencies = [
#    "cairosvg",
#    "pillow",
# ]
# ///


import os
import sys
import shutil
import pathlib
import io
import shutil
import subprocess
import shlex

import cairosvg
import PIL

def die(msg):
  print(msg)
  sys.exit(1)

def pretty_cmd(*cmd, **kwargs):
  debug_cmd_txt = shlex.join(cmd)
  print(f'> {debug_cmd_txt}')
  subprocess.run(list(cmd), **kwargs)

def render_svg_to_png_bytes(svg_path, size):
    '''Render SVG to PNG bytes at a given size.'''
    return cairosvg.svg2png(url=svg_path, output_width=size, output_height=size)


def write_png(out_dir, size, png_bytes):
    path = pathlib.Path( os.path.join(out_dir, f'icon_{size}x{size}.png') )
    path.write_bytes(png_bytes)
    print(f'Wrote {path}')


def generate_pngs(svg_path, out_dir):
    for size in PNG_SIZES:
        png = render_svg_to_png_bytes(svg_path, size)
        write_png(out_dir, size, png)

def generate_ico(svg_path, out_dir):
    '''Create a multi-resolution Windows .ico file.'''
    images = []

    for size in sorted(ICO_SIZES, reverse=True):
        png_bytes = render_svg_to_png_bytes(svg_path, size)
        img = PIL.Image.open(io.BytesIO(png_bytes)).convert('RGBA')
        images.append(img)

    ico_path = os.path.join(out_dir, 'icon.ico')
    images[0].save(
        ico_path,
        format="ICO",
        append_images=images[1:]
    )
    print(f'Wrote {ico_path}')

    return ico_path

def generate_go_rsrc_syso(ico_file, go_src_folder):
  if shutil.which('rsrc') is None:
    # Fix attempt 1: Add $HOME/go/bin to $PATH
    go_bin = pathlib.Path.home() / "go" / "bin"
    path_parts = os.environ.get('PATH', '').split(os.pathsep)
    path_parts.append(go_bin)
    os.environ['PATH'] = os.pathsep.join(str(p) for p in path_parts if p)

  if shutil.which('rsrc') is None:
    pretty_cmd(
      'go', 'install', 'github.com/akavel/rsrc@latest',
    )

  if shutil.which('rsrc') is None:
    die(f'Please install the binary rsrc!')

  syso_file = os.path.join(go_src_folder, 'rsrc.syso')
  pretty_cmd(
    shutil.which('rsrc'), '-ico', ico_file, '-o', syso_file
  )
  print(f'Generated {syso_file}')


graphics_folder = os.path.dirname(os.path.realpath(__file__))
go_src_folder = os.path.join(os.path.dirname(graphics_folder), 'av-switchyard')

primary_svg = os.path.join(graphics_folder, 'icon-primary.svg')

# Standard GUI icon sizes
PNG_SIZES = [16, 32, 48, 64, 128, 256]
# Windows ICO should include multiple sizes
ICO_SIZES = [16, 32, 48, 64, 128, 256]


graphics_build_folder = os.path.join(graphics_folder, 'build')
os.makedirs(graphics_build_folder, exist_ok=True)

if not os.path.exists(primary_svg):
  die(f'Please create the primary icon file, {primary_svg}')

generate_pngs(primary_svg, graphics_build_folder)
ico_file = generate_ico(primary_svg, graphics_build_folder)
generate_go_rsrc_syso(ico_file, go_src_folder)
