#!/bin/sh

usage1="usage: hostscan network-address(24bit-length)"
usage2="ex.    hostscan 192.168.0"
usage3="       hostscan 192.168.1.100"

if [ $# -ne 1 ]; then
  printf "%s\n%s\n%s\n" "$usage1" "$usage2" "$usage3"
  exit 1
fi

echo $1 | grep "\([1-9]\?[0-9]\|1[0-9][0-9]\|2[0-4][0-9]\|25[0-5]\)\.\([1-9]\?[0-9]\|1[0-9][0-9]\|2[0-4][0-9]\|25[0-5]\)\.\([1-9]\?[0-9]\|1[0-9][0-9]\|2[0-4][0-9]\|25[0-5]\)\.\?\([[1-9]\?[0-9]\|1[0-9][0-9]\|2[0-4][0-9]\|25[0-5]]\)\?$" > /dev/null
if [ $? -ne 0 ]; then
  printf "%s\n%s\n%s\n" "$usage1" "$usage2" "$usage3"
  exit 1
fi

network=`echo $1 | cut -d "." -f 1-3`
host=`echo $1 | cut -d "." -f 4`
if [ "$host" = "" ]; then
  host=0
fi

case `uname` in
Darwin)
  options="-c 1 -W 1 "
  ;;
Linux)
  options="-c 1 -w 1 -q"
  ;;
CYGWIN* | MINGW*)
  options="-c 1 -w 1 -q"
  ;;
esac

while [ $host -lt 255 ]; do
  ping $options $network.$host >& /dev/null && echo $network.$host &
  host=`expr $host + 1`
done
