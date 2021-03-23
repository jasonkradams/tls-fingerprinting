#!/usr/bin/env python

# Based off:
# https://devcentral.f5.com/s/articles/tls-fingerprinting-a-method-for-identifying-a-tls-client-without-decrypting-24598

# Converting this file from JSON format to an F5 BIG-IP external data-group
#  https://raw.githubusercontent.com/LeeBrotherston/tls-fingerprinting/master/fingerprints/fingerprints.json

import json
import re

f = open('fingerprints.json', 'r')

def sanitizer(line):
  line = re.sub('\\\\//','/',line)
  line = re.sub('[{}"\s,]|0x','', line)
 
  return line

# Each line is it's own JSON object
for line in f.readlines():
  line = json.loads(line)

  # Not all records are present in every line
  # Set value to @@@@ if the property is not present.
  record_tls_version = line['record_tls_version'] if 'record_tls_version' in line else '@@@@'
  tls_version        = line['tls_version']        if 'tls_version'        in line else '@@@@'
  ciphersuite_length = line['ciphersuite_length'] if 'ciphersuite_length' in line else '@@@@'
  ciphersuite        = line['ciphersuite']        if 'ciphersuite'        in line else '@@@@'
  compression_length = line['compression_length'] if 'compression_length' in line else '@@@@'
  compression        = line['compression']        if 'compression'        in line else '@@@@'
  extensions         = line['extensions']         if 'extensions'         in line else '@@@@'
  e_curves           = line['e_curves']           if 'e_curves'           in line else '@@@@'
  sig_alg            = line['sig_alg']            if 'sig_alg'            in line else '@@@@'
  ec_point_fmt       = line['ec_point_fmt']       if 'ec_point_fmt'       in line else '@@@@'
  desc               = line['desc']               if 'desc'               in line else '@@@@'

  # Sanitize
  record_tls_version  = sanitizer(str(record_tls_version  ).encode('UTF-8').lower())
  tls_version         = sanitizer(str(tls_version         ).encode('UTF-8').lower())
  ciphersuite_length  = sanitizer(str(ciphersuite_length  ).encode('UTF-8').lower())
  ciphersuite         = sanitizer(str(ciphersuite         ).encode('UTF-8').lower())
  compression_length  = sanitizer(str(compression_length  ).encode('UTF-8').lower())
  compression         = sanitizer(str(compression         ).encode('UTF-8').lower())
  extensions          = sanitizer(str(extensions          ).encode('UTF-8').lower())
  e_curves            = sanitizer(str(e_curves            ).encode('UTF-8').lower())
  sig_alg             = sanitizer(str(sig_alg             ).encode('UTF-8').lower())
  ec_point_fmt        = sanitizer(str(ec_point_fmt        ).encode('UTF-8').lower())

  # Set to a format we can digest in a data-group
  print('"' + record_tls_version + '+' + tls_version + '+' + ciphersuite_length + '+' + ciphersuite + '+' + compression_length + '+' + compression + '+' + extensions + '+' + e_curves + '+' + sig_alg + '+' + ec_point_fmt + '" := "' + desc + '",')

f.close()
