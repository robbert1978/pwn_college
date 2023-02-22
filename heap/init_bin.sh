#!/bin/sh
if [ -z $1  ]
then
    echo "$0 <bin-file>"
else
    patchelf --set-interpreter ../ld-2.31.so --set-rpath .. "$1"
fi