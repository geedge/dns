#!/bin/sh
DST=${RPM_INSTALL_PREFIX}
mkdir -p ${DST}/plug/protocol/
mkdir -p  ${DST}/etc/
touch ${DST}/plug/conflist.inf
touch ${DST}/etc/entrylist.conf
if [[ -z `grep -rn 'dns.inf' ${DST}/plug/conflist.inf` ]];then
	sed -i '/\[protocol\]/a\./plug/protocol/dns/dns.inf' ${DST}/plug/conflist.inf
fi
if [[ -z `grep -rn 'DNS' ${DST}/etc/entrylist.conf` ]];then
	echo "DNS" >>  ${DST}/etc/entrylist.conf
fi
