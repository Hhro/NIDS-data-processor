#!/usr/bin/env python
import argparse
import pyshark
import shutil
import csv
import time
import numpy as np
from pathlib import Path
from packet_array import PktArray

sess_next = 1
packet_cnt = 1


def process_pcap(pcap_path, output_dir_path, writers, mtu=1500):
    '''
    Description: Process pcap file into 'labels.csv', 'sess.csv' and 'pkts.npy'

    Args:
    @pcap_path: Path instance of pcap path
    @output_dir_path: Path instance of output directory
    @writers: Output writers of 'labels.csv' and 'sess.csv'
    @mtu: maximum transmission unit (default=1500)
    '''

    global sess_next
    global packet_cnt

    # Performance monitoring
    start_time = time.time()

    # Data label: filename without extension
    label = Path(pcap_path).stem

    print("\n\t[+]Process pcap '{}({}MiB)'".format(label,
                                                   pcap_path.stat().st_size >> 20))
    print("\tStart at: {}".format(time.ctime()))

    # Some pcaps are splitted into "label-1.pcap, label-2.pcap ..."
    if "-" in label:
        label = label[:label.index("-")]

    # Empty pkt array and session map
    # sessions = {pkt.tcp.stream: session_number}
    pkts_array = PktArray(mtu)
    sessions = {}

    # Check if there is preceded data
    if (output_dir_path / (label + ".npy")).exists():
        base_npy_reader = (output_dir_path / (label + ".npy")).open("rb")
        base_npys = np.load(base_npy_reader)

        for base_npy in base_npys:
            pkts_array.add(base_npy)

        base_npy_reader.close()

    # keep_packets=False : prevent memory leak
    # include_raw=True : raw packet data would be appended to pcap_numpy
    pkts = pyshark.FileCapture(
        str(pcap_path), keep_packets=False, use_json=True, include_raw=True)

    for pkt in pkts:
        # We only care TCP packet
        if "TCP" not in str(pkt.layers):
            continue

        pkt_id = packet_cnt
        pkt_length = pkt.length
        pkt_label = label
        pkt_src_ip = pkt.ip.src
        pkt_src_port = pkt.tcp.srcport
        pkt_dst_ip = pkt.ip.dst
        pkt_dst_port = pkt.tcp.dstport

        # Session numbering:
        # Same session number can be exist across different pcap files.
        # This numbering method would generate unique session number.
        if pkt.tcp.stream in sessions.keys():
            pkt_sess_id = sessions[pkt.tcp.stream]
        else:
            pkt_sess_id = sess_next

            sessions.update({pkt.tcp.stream: sess_next})
            sess_next += 1

            # Append session data to 'sess.csv'
            writers[1].writerow(
                [pkt_sess_id, pkt_src_ip, pkt_src_port, pkt_dst_ip, pkt_dst_port])

        # Append labeled packet data to 'labels.csv'
        writers[0].writerow([pkt_id, pkt_sess_id, pkt_length, pkt_label])

        pkts_array.add(np.frombuffer(pkt.get_raw_packet(), dtype=np.uint8))

        packet_cnt += 1

    # Save(append) pcap numpy array into [label].npy
    npy_writer = (output_dir_path / (label + ".npy")).open("wb")
    np.save(npy_writer, pkts_array.finalize())
    npy_writer.close()

    # Troulbeshooting for 'This event loop is ...'
    pkts.close()

    end_time = time.time()
    print("\tEnd at: {}".format(time.ctime()))
    print("\tElapsed time: {}\n".format(time.strftime(
        "%H:%M:%S", time.gmtime(end_time-start_time))))


def process_pcaps(pcap_dir_path, output_dir_path, writers, mtu=1500):
    '''
    Description:
        Process pcaps included in 'pcap_dir_path' recursively.
        Each pcap would generate its own '[label].npy'

    Args:
    @pcap_dir_path: Path instance of pcap directory
    @output_dir_path: Path instance of output directory
    @writers: Output writers of 'labels.csv' and 'sess.csv'
    @mtu: maximum transmission unit(default=1500)
    '''

    # Gather pcaps
    pcap_paths = sorted(list(pcap_dir_path.glob("**/*.pcap")))

    # Perf & brief info
    start_time = time.time()
    total_pcap_sz = sum(
        pcap.stat().st_size for pcap in pcap_paths if pcap.is_file())

    print("\n[+]Process pcaps in '{}({}GiB)'".format(str(pcap_dir_path),
                                                     total_pcap_sz >> 30))
    print("Start at: {}".format(time.ctime()))

    # Process each pcap
    for path in pcap_paths:
        process_pcap(path, output_dir_path, writers, mtu)

    print("Total packet counts: {}".format(packet_cnt-1))
    print("Total session counts: {}".format(sess_next-1))

    end_time = time.time()
    print("End at: {}".format(time.ctime()))
    print("Elapsed time: {}\n".format(time.strftime(
        "%H:%M:%S", time.gmtime(end_time-start_time))))


if __name__ == "__main__":
    # Argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--pcap", help="Input pcap file")
    parser.add_argument("-d", "--pcap_dir", help="Input pcap directory")
    parser.add_argument("-o", "--output", default="output",
                        help="Output directory")
    parser.add_argument("-m", "--mtu", default=1500, type=int)

    args = parser.parse_args()

    # MTU is optional
    mtu = args.mtu

    # Initialize Path variables
    pcap_path = ''
    pcap_dir_path = ''

    output_dir_path = Path(args.output).resolve()

    # Clean output directory
    if output_dir_path.exists():
        shutil.rmtree(str(output_dir_path))

    output_dir_path.mkdir(parents=True, exist_ok=True)
    output_paths = [output_dir_path / "labels.csv",
                    output_dir_path / "sess.csv",
                    ]

    # Initialize IO variables
    writers = []
    writers.append(csv.writer(output_paths[0].open("w")))
    writers.append(csv.writer(output_paths[1].open("w")))

    # One of pcap or pcap_dir is required
    if not args.pcap and not args.pcap_dir:
        quit()

    # Process only one pcap
    if args.pcap:
        pcap_path = Path(args.pcap).resolve()

        if not pcap_path.exists():
            print("[!] Pcap '{}' is not exist".format(str(pcap_path)))
            quit()

        process_pcap(pcap_path, output_dir_path, writers, mtu)

    # Process every pcaps included in pcap_dir recursively
    elif args.pcap_dir:
        pcap_dir_path = Path(args.pcap_dir).resolve()

        if not pcap_dir_path.exists():
            print("[!] Pcap directory '{}' doesn't exist ".format(
                str(pcap_dir_path)))
            quit()
        if not pcap_dir_path.is_dir():
            print("[!] Pcap directory '{}' is not a directory.".format(
                str(pcap_dir_path)))
            quit()

        process_pcaps(pcap_dir_path, output_dir_path, writers, mtu)
