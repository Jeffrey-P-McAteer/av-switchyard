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

import cairosvg
import PIL

def die(msg):
  print(msg)
  sys.exit(1)

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

graphics_folder = os.path.dirname(os.path.realpath(__file__))

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
generate_ico(primary_svg, graphics_build_folder)

