# coding: utf-8
import random
import os
import sys
import re
import zipfile
import tempfile
import shutil
from xml.dom.minidom import parse, parseString
from scapy.utils import PcapWriter
from scapy.all import *
import glob
from optparse import OptionParser
import logging

class ComparePcapAndSaz(object):
    """
    比较pcap文件和saz文件，将相同的数据流对应起来，输出无法对应起来的部分
    """
    def __init__(self):
        self.opts2args = self.parser_option()
        # print self.opts2args
        self.extract_saz()

    def parser_option(self):
        """
        解析主程序的输入参数
        :return:dict 输入参数的键值对
        """
        parser = OptionParser()
        parser.add_option("--pcap", dest="input_pcap", type="string", help="path to pcap file")
        parser.add_option("--saz", dest="input_saz", type="string", help="path to saz file")
        parser.add_option("-o", dest="output_pcap", type="string", help="output file name")

        (options, args) = parser.parse_args()
        if options == []:
            print parser.print_help()
            sys.exit(-1)
        if not options.input_pcap or options.input_pcap == "":
            print parser.print_help()
            sys.exit(-1)
        if not options.input_saz or options.input_saz == "":
            print parser.print_help()
            sys.exit(-1)
        if not options.output_pcap or options.output_pcap == "":
            print parser.print_help()
            sys.exit(-1)

        return options

    def extract_saz(self):
        """
        将saz文件解压
        :return:
        """
        # 如果输入是saz文件则解压
        if os.path.isfile(self.opts2args.input_saz):
            try:
                self.opts2args.tmpdir = tempfile.mkdtemp()
                logging.info("创建临时文件夹%s", self.opts2args.tmpdir)
            except:
                logging.info("创建临时文件夹失败")
                sys.exit(-1)
            try:
                z = zipfile.ZipFile(self.opts2args.input_saz, "r")
                logging.info("打开saz文件 %s", self.opts2args.input_saz)
            except:
                logging.info("打开saz文件失败 %s", self.opts2args.input_saz)
                sys.exit(-1)
            try:
                z.extractall(self.opts2args.tmpdir)
                z.close()
                logging.info("将%s文件解压到%s", self.opts2args.input_saz, self.opts2args.tmpdir)
            except:
                logging.info("将%s文件解压到%s失败", self.opts2args.input_saz, self.opts2args.tmpdir)
                sys.exit(-1)
            if os.path.isdir("%s/raw/" % (self.opts2args.tmpdir)):
                self.opts2args.fiddler_raw_dir = "%s/raw/" % (self.opts2args.tmpdir)
            else:
                logging.info("在解压后的临时文件夹中没有找到%s/raw (需要手动删除临时文件夹)", self.opts2args.tmpdir)
                sys.exit(-1)

        # 如果输入是文件夹，则默认是fiddler的raw文件夹
        elif os.path.isdir(self.opts2args.input_saz):
            self.opts2args.fiddler_raw_dir = self.opts2args.input_saz
            self.opts2args.tmpdir = None
        else:
            raise Exception("输入saz的路径既不是.saz文件也不是文件夹！")

        logging.info("fiddler的raw文件准备完毕")

    def remove_tmpdir(self):
        if self.opts2args.tmpdir:
            try:
                shutil.rmtree(self.opts2args.tmpdir)
                logging.info("删除tmpdir %s", self.opts2args.tmpdir)
            except:
                logging.info("删除tmpdir %s 失败", self.opts2args.tmpdir)
