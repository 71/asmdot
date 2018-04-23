import os.path
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from common import args

if args.x86 + args.arm == 0:
    print("No architecture given.", file=sys.stderr)
    
    exit(1)


if args.x86:
    from x86 import translate_all

    translate_all()

if args.arm:
    from arm import translate_all

    translate_all()
