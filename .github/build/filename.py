#!/usr/bin/python

import sys

OS = sys.argv[1]
ARCH = sys.argv[2]
ARM = sys.argv[3]
MISP = sys.argv[4]

if (ARM != ""):
  print("Xray-{}-armv{}".format(OS, ARM))
elif (MISP != ""):
  print("Xray-{}-{}-{}".format(OS, ARCH, MISP))
else:
  print("Xray-{}-{}".format(OS, ARCH))