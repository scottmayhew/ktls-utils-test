#!/bin/bash
#
# Basic RPC-with-TLS testing.
#
# openssl configs and commands based on https://pki-tutorial.readthedocs.io/
#
MYOLDHOSTNAME=$(hostnamectl hostname --static)
MYHOSTNAME=nfs.ktls-utils.test
MYIP=$(ip -o route get to 8.8.8.8 | sed -n 's/.*src \([0-9.]\+\).*/\1/p')
OCSP_PID=0

cleanup() {
	echo "Cleanup..."
	hostnamectl hostname --static "$MYOLDHOSTNAME"
	exportfs -ua
	systemctl stop nfs-server
	rm -rf /export
	systemctl stop tlshd
	cp /etc/tlshd.conf.bak /etc/tlshd.conf
	rm -f /etc/pki/tls/certs/ktls.pem
	rm -f /etc/pki/tls/certs/signing-ca.crt
	rm -f /etc/pki/tls/private/ktls.key
	rm -rf ca certs crl
	if [ $OCSP_PID -ne 0 ]; then
		kill $OCSP_PID
	fi
}

trap cleanup EXIT
trap cleanup INT

echo "Setup..."
hostnamectl hostname --static "$MYHOSTNAME"
cp /etc/tlshd.conf /etc/tlshd.conf.bak

echo "Create root CA directories"
mkdir -p ca/root-ca/private ca/root-ca/db crl certs
chmod 700 ca/root-ca/private

echo "Create root CA database"
cp /dev/null ca/root-ca/db/root-ca.db
echo 01 > ca/root-ca/db/root-ca.crt.srl
echo 01 > ca/root-ca/db/root-ca.crl.srl

echo "Create root CA key and request"
openssl req -new \
	-config etc/root-ca.conf \
	-out ca/root-ca.csr \
	-keyout ca/root-ca/private/root-ca.key \
	-noenc >/dev/null 2>&1

echo "Create root CA certificate"
openssl ca \
	-selfsign \
	-config etc/root-ca.conf \
	-in ca/root-ca.csr -out ca/root-ca.crt \
	-extensions root_ca_ext -batch

cp ca/root-ca.crt /var/www/html

echo "Create signing CA directories"
mkdir -p ca/signing-ca/private ca/signing-ca/db crl certs
chmod 700 ca/signing-ca/private

echo "Create signing CA database"
cp /dev/null ca/signing-ca/db/signing-ca.db
echo 01 > ca/signing-ca/db/signing-ca.crt.srl
echo 01 > ca/signing-ca/db/signing-ca.crl.srl

echo "Create signing CA key and request"
openssl req -new \
	-config etc/signing-ca.conf \
	-out ca/signing-ca.csr \
	-keyout ca/signing-ca/private/signing-ca.key \
	-noenc >/dev/null 2>&1

echo "Create signing CA certificate"
openssl ca \
	-config etc/root-ca.conf \
	-in ca/signing-ca.csr -out ca/signing-ca.crt \
	-extensions signing_ca_ext -batch

cp ca/signing-ca.crt /var/www/html

echo "Generate initial CRL"
openssl ca -gencrl \
	-config etc/signing-ca.conf \
	-out crl/signing-ca.crl

echo "Copy initial CRL to distribution point"
cp crl/signing-ca.crl /var/www/html

echo "Copy initial CRL to /etc/pki/crl"
[ ! -d /etc/pki/crl ] && mkdir /etc/pki/crl
cp crl/signing-ca.crl /etc/pki/crl

echo "Create OCSP signing key and request"
openssl req -new \
	-config etc/ocspsign.conf \
	-out certs/signing-ca-ocsp.csr \
	-keyout certs/signing-ca-ocsp.key >/dev/null 2>&1

echo "Create OCSP signing certificate"
openssl ca \
	-config etc/signing-ca.conf \
	-in certs/signing-ca-ocsp.csr -out certs/signing-ca-ocsp.crt \
	-extensions ocspsign_ext -days 14 -batch

echo "Start OCSP responder"
openssl ocsp \
	-url http://${MYHOSTNAME}:8888 \
	-index ca/signing-ca/db/signing-ca.db \
	-CA ca/signing-ca.crt \
	-rsigner certs/signing-ca-ocsp.crt \
	-rkey certs/signing-ca-ocsp.key \
	-ndays 1 &

OCSP_PID=$!

echo "Create kTLS key and request"
openssl req -new \
	-newkey rsa:4096 \
	-subj "/CN=${MYHOSTNAME}/DC=com/DC=redhat/O=Red Hat Inc/OU=NFS Team" \
	-addext "subjectAltName=DNS:${MYHOSTNAME},IP:${MYIP}" \
	-out certs/ktls.req \
	-keyout certs/ktls.key \
	-noenc >/dev/null 2>&1

echo "Create kTLS certificate with 30 second lifetime"
ENDDATE=$(date --date=@$(( $(date +%s) + 30 )) --universal +%y%m%d%H%M%SZ)
openssl ca \
	-config etc/signing-ca.conf \
	-in certs/ktls.req -out certs/ktls.pem \
	-extensions server_ext -batch -enddate $ENDDATE

cp ca/signing-ca.crt /etc/pki/tls/certs
cp certs/ktls.pem /etc/pki/tls/certs
cp certs/ktls.key /etc/pki/tls/private

cat <<EOF >/etc/tlshd.conf
[debug]
loglevel=9
tls=9
nl=9

[authenticate]
#keyrings= <keyring>;<keyring>;<keyring>

[authenticate.client]
x509.truststore=/etc/pki/tls/certs/signing-ca.crt
x509.crl=/etc/pki/crl/signing-ca.crl
x509.certificate=/etc/pki/tls/certs/ktls.pem
x509.private_key=/etc/pki/tls/private/ktls.key

[authenticate.server]
x509.truststore=/etc/pki/tls/certs/signing-ca.crt
x509.crl=/etc/pki/crl/signing-ca.crl
x509.certificate=/etc/pki/tls/certs/ktls.pem
x509.private_key=/etc/pki/tls/private/ktls.key
EOF

systemctl restart tlshd
systemctl restart nfs-server
mkdir /export
exportfs -o rw,insecure,no_root_squash,xprtsec=tls:mtls *:/export

# mount by hostname
echo "Try to mount $MYHOSTNAME:/export without xprtsec=tls"
mount -o v4.2 $MYHOSTNAME:/export /mnt
if [ $? -eq 0 ]; then
	echo "Mounted $MYHOSTNAME:/export without xprtsec=tls!"
	exit 1
fi

echo "Try to mount $MYHOSTNAME:/export with xprtsec=tls"
mount -o v4.2,xprtsec=tls $MYHOSTNAME:/export /mnt
if [ $? -ne 0 ]; then
	echo "Failed to mount $MYHOSTNAME:/export with xprtsec=tls!"
	exit 1
fi

if ! grep "xprtsec=tls" /proc/mounts; then
	echo "Failed to find xprtsec=tls in /proc/mounts"
	exit 1
fi
echo "Mounted $MYHOSTNAME:/export with xprtsec=tls at $(date)" >/mnt/file
umount /mnt

# mount by ip address
echo "Try to mount $MYIP:/export without xprtsec=tls"
mount -o v4.2 $MYIP:/export /mnt
if [ $? -eq 0 ]; then
	echo "Mounted $MYIP:/export without xprtsec=tls!"
	exit 1
fi

echo "Try to mount $MYIP:/export with xprtsec=tls"
mount -o v4.2,xprtsec=tls $MYIP:/export /mnt
if [ $? -ne 0 ]; then
	echo "Failed to mount $MYIP:/export with xprtsec=tls!"
	exit 1
fi

if ! grep "xprtsec=tls" /proc/mounts; then
	echo "Failed to find xprtsec=tls in /proc/mounts"
	exit 1
fi
echo "Mounted $MYIP:/export with xprtsec=tls at $(date)" >>/mnt/file

echo "Sleeping 31 seconds"
sleep 31

echo "Try to write after cert expired."
echo "Wrote after cert expired at $(date)" >>/mnt/file
umount /mnt

echo "Try to mount $MYHOSTNAME:/export with xprtsec=tls after cert expired."
mount -o v4.2,xprtsec=tls $MYHOSTNAME:/export /mnt
if [ $? -eq 0 ]; then
	echo "Mounted $MYHOSTNAME:/export with xprtsec=tls after cert expired!"
	echo "Mounted $MYHOSTNAME:/export with xprtsec=tls after cert expired at $(date)" >>/mnt/file
	umount /mnt
	exit 1
fi

echo "Create new kTLS certificate with default lifetime"
openssl ca \
	-config etc/signing-ca.conf \
	-in certs/ktls.req -out certs/ktls.pem \
	-extensions server_ext -batch

cp certs/ktls.pem /etc/pki/tls/certs

echo "Try to mount $MYHOSTNAME:/export with xprtsec=tls after signing new cert"
mount -o v4.2,xprtsec=tls $MYHOSTNAME:/export /mnt
if [ $? -ne 0 ]; then
	echo "Failed to mount $MYHOSTNAME:/export with xprtsec=tls after signing new cert!"
	exit 1
fi

if ! grep "xprtsec=tls" /proc/mounts; then
	echo "Failed to find xprtsec=tls in /proc/mounts"
	exit 1
fi
echo "Mounted $MYHOSTNAME:/export with xprtsec=tls after signing new cert at $(date)" >>/mnt/file
umount /mnt

echo "Revoke kTLS certificate"
openssl ca \
	-config etc/signing-ca.conf \
	-revoke certs/ktls.pem \
	-crl_reason keyCompromise

echo "Generate updated CRL"
openssl ca -gencrl \
	-config etc/signing-ca.conf \
	-out crl/signing-ca.crl

echo "Copy updated CRL to distribution point"
cp crl/signing-ca.crl /var/www/html

echo "Copy updated CRL to /etc/pki/crl"
cp crl/signing-ca.crl /etc/pki/crl

echo "Check CRL"
SERIAL=$(openssl x509 -in /etc/pki/tls/certs/ktls.pem -noout -serial|awk -F= '{ print $2 }')
curl http://nfs.ktls-utils.test/signing-ca.crl | openssl crl -noout -text | grep -A4 $SERIAL

# This is weird.  The first time you check the OCSP responder, it says the cert status is "unknown".
# So we'll just check it twice. ¯\_(ツ)_/¯
echo "Check OCSP responder"
openssl ocsp \
	-url http://nfs.ktls-utils.test:8888 \
	-CAfile ca/root-ca.crt \
	-issuer ca/signing-ca.crt \
	-cert /etc/pki/tls/certs/ktls.pem

echo "Check it again"
openssl ocsp \
	-url http://nfs.ktls-utils.test:8888 \
	-CAfile ca/root-ca.crt \
	-issuer ca/signing-ca.crt \
	-cert /etc/pki/tls/certs/ktls.pem

echo "Try to mount $MYHOSTNAME:/export with xprtsec=tls after revoking cert"
mount -o v4.2,xprtsec=tls $MYHOSTNAME:/export /mnt
if [ $? -eq 0 ]; then
	echo "Mounted $MYHOSTNAME:/export with xprtsec=tls after revoking cert!"
	echo "This is expected in ktls-utils releases prior to 1.2.0, because tlshd did not implement CRL checking."
	echo "Note that no versions of ktls-utils currently implement OCSP checking."
	umount /mnt
fi

echo "Success!"
exit 0
