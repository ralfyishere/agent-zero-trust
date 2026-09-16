"""Measure a frozen sensitive-request pack with an explicit installed CLI.

Challenge is the default; development results must be separate. A mismatch is
recorded, not repaired or hidden. No fixture instructions are executed.
"""
import argparse

from sensitive_request_lab import run_lab


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cli', required=True, help='explicit executable from the installed candidate')
    parser.add_argument('--output', required=True, help='new private result directory outside fixtures')
    parser.add_argument('--pack', choices=('challenge-v1', 'development-v1'), default='challenge-v1')
    parser.add_argument('--baseline', action='store_true', help='measure historical observations without candidate schema/metadata assertions')
    args = parser.parse_args()
    result = run_lab(args.cli, args.output, pack=args.pack, include_workflows=False, baseline=args.baseline)
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
