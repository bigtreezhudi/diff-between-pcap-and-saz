# coding: utf-8
import logging
from ComparePcapAndSaz import ComparePcapAndSaz
from scapy.all import PcapReader, wrpcap, Packet, NoPayload
from scapy.utils import PcapWriter


def main():
    comparator = ComparePcapAndSaz()
    comparator.parse_saz()
    comparator.parse_pcap()
    comparator.remove_tmpdir()

def find_no_proxy_packets(pcap_file, proxy_ip, output_file):
    """
    读取pcap文件，将其中不走代理的packet保存到一个pcap文件中
    """
    dump = PcapWriter(output_file, sync=True)
    with PcapReader(pcap_file) as pcap_reader:
        for packet in pcap_reader:
            if 'IP' in packet:
                src = packet['IP'].fields['src']
                dst = packet['IP'].fields['dst']

                if 'TCP' in packet:
                    sport = packet['TCP'].fields['sport']
                    dport = packet['TCP'].fields['dport']
                elif 'UDP' in packet:
                    sport = packet['UDP'].fields['sport']
                    dport = packet['UDP'].fields['dport']
                else:
                    logging.debug("没有TCP或UDP")
                    continue
            else:
                logging.debug("没有IP层")
                continue
            if not ((src == proxy_ip and sport == 8888) or (dst == proxy_ip and dport == 8888)):
                dump.write(packet)
    dump.close()

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        format='[%(asctime)s][%(levelname)s][%(filename)s:%(lineno)d]%(message)s',
                        datefmt='%m-%d %H:%M')
    # main()
    find_no_proxy_packets('night.pcap', '10.42.0.144', 'no_proxy_packets_of_night.pcap')