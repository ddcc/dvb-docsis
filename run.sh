#!/bin/sh

until ../../../binaries/tools/dvb-docsis; do
	echo "Restarting..."
	sleep 1
done
