#!/usr/bin/python

import sys
import re
from optparse import OptionParser

re_guid = re.compile(r'0x(?P<guid>[0-9,a-f]{16})', re.IGNORECASE)
re_lid = re.compile(r'base LID (?P<lid>[0-9]+)', re.IGNORECASE)

def read_blocks(input_file,delete_description):
	node_lines = 0
	blocks = {}
	lid = 0
	for line in open(input_file):
		line = line.rstrip('\n')
		m = re_lid.search(line)
		if m:
			node_lines += 1
			lid_str = m.group('lid')
			lid = int(lid_str)
			blocks[lid] = []
			if delete_description:
				line = re.sub(r'\".*\", ','',line)
		if lid<>0:
			blocks[lid].append(line)
	lids = blocks.keys()
	lids.sort()
	for lid in lids:
		for line in blocks[lid]:
			print line

def main():
	usage = "usage: %prog [options] arg"
	parser = OptionParser(usage)
	parser.add_option("-d","--delete-description",help="delete node description",action="store_true",dest="delete_description")

	(options,args) = parser.parse_args()
	if len(args) < 1:
		parser.error("incorrect number of arguments")

	inputfile = args[0]

	read_blocks(inputfile,options.delete_description)

if __name__ == "__main__":
	main()
