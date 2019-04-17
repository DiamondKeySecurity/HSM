#!/usr/bin/env python
# Copyright (c) 2019  Diamond Key Security, NFP
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; version 2
# of the License only.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, If not, see <https://www.gnu.org/licenses/>.


import os
import subprocess


class HSMSecurity(object):
    def create_certs_if_not_exist(self, private_key_name, certificate_name):
        if(os.path.exists(private_key_name) is False or
           os.path.exists(certificate_name) is False):
            return self.create_tls_certs(private_key_name, certificate_name)
        else:
            return True

    def create_tls_certs(self, private_key_name, certificate_name):
        """Use OpenSSL to create self-signed certificate"""

        # make sure the paths exist. Usually the same but can be different
        private_path = os.path.dirname(private_key_name)
        cert_path = os.path.dirname(certificate_name)

        try:
            os.makedirs(private_path)
        except OSError as e:
            if not os.path.isdir(private_path):
                raise

        try:
            os.makedirs(cert_path)
        except OSError as e:
            if not os.path.isdir(cert_path):
                raise

        # options for openssl
        openssl_params = ['/usr/bin/openssl ',
                          'req ',
                          '-newkey rsa:2048 ',
                          '-nodes ',
                          '-keyout %s '%private_key_name,
                          '-x509 ',
                          '-days 365 ',
                          '-out %s'%certificate_name,
                         ]

        # options for the certificate
        input = 'US\nIllinois\nPalatine\nDiamond Key Security, NFP\nHSM Development\ndks-hsm\ndouglas@dkey.org\n'

        try:
            with open(os.devnull, 'w') as FNULL:
                proc = subprocess.Popen(["".join(openssl_params)], stdin=subprocess.PIPE, stdout=FNULL, stderr=FNULL, shell=True)

                proc.communicate(input)
        except:
            return False
        
        return True

    def extract_signed_update(self, src_path, extracted_path, digest_path, public_key_path):
        if(self.split_file(src_path, extracted_path, digest_path, 512) is True):
            # options for openssl
            openssl_params = ['/usr/bin/openssl ',
                            'dgst -sha512 ',
                            '-verify %s '%public_key_path,
                            '-signature %s '%digest_path,
                            '%s'%extracted_path
                            ]

            try:
                with open(os.devnull, 'w') as FNULL:
                    proc = subprocess.Popen(["".join(openssl_params)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=FNULL, shell=True)

                    out, err = proc.communicate(None)
            except:
                return False
            
            return 'Verified OK' in out

        return False

    def split_file(self, src_path, dst_file1, dst_file2, dst_file2_size):
        try:
            size = os.path.getsize(src_path) - dst_file2_size

            """split the source file into 2"""
            with open(src_path, "rb") as src_fp:
                with open(dst_file1, "wb") as dst1_fp:
                    for i in xrange(size):
                        dst1_fp.write(src_fp.read(1))
                with open(dst_file2, "wb") as dst2_fp:
                    for i in xrange(dst_file2_size):
                        dst2_fp.write(src_fp.read(1))
        except IOError as e:
            return e.message

        return True





if __name__ == "__main__":
    security = HSMSecurity().create_certs_if_not_exist(private_key_name = '/home/douglas/Documents/TEMP/domain.key',
                                                       certificate_name = '/home/douglas/Documents/TEMP/domain.crt')

    print security

    print HSMSecurity().extract_signed_update('/home/douglas/Documents/TEMP/2018-11-16-05-DKEY-HSM-UPDATE.tar.gz.signed',
                                   '/home/douglas/Documents/TEMP/2018-11-16-05-DKEY-HSM-UPDATE.tar.gz',
                                   '/home/douglas/Documents/TEMP/digest', 
                                   '/home/douglas/Documents/TEMP/dkey-public.pem')