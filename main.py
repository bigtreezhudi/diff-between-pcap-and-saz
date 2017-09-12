# coding: utf-8
import logging
from ComparePcapAndSaz import ComparePcapAndSaz


def main():
    comparator = ComparePcapAndSaz()
    comparator.remove_tmpdir()

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        format='[%(asctime)s][%(levelname)s][%(filename)s:%(lineno)d]%(message)s',
                        datefmt='%m-%d %H:%M')
    main()