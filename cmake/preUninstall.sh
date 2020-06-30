#!/bin/sh
if [ $1 == 0 ]; then
	DST=${RPM_INSTALL_PREFIX}

	mkdir -p ${DST}/plug/business/
	touch ${DST}/plug/conflist.inf

	sed -i '/dns.inf/d' ${DST}/plug/conflist.inf
	sed -i '/DNS/d' ${DST}etc/entrylist.conf
fi
