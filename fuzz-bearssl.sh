#!/bin/bash

if [ -z "$1" ] || [ -z "$2" ]; then
  echo "Usage: $0 <STAGE1_TIMEOUT> <STAGE2_N_SECRETS>"
  exit -1
fi

BASE_PATH=/home/alvise/sw-testing/

export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_PATH=$BASE_PATH/AFLplusplus
export BEARSSL_PATH=$BASE_PATH/BearSSL/

CONFIG=consfuzz.yaml
RESULTS=$BASE_PATH/results/latest
CMD=$BASE_PATH/rvzr-sw-eval/drivers/bearssl/bearssl
INPUT=$BASE_PATH/rvzr-sw-eval/drivers/bearssl/test/iv.bin

# rm -rf $RESULTS
# mkdir -p $RESULTS

set -e
set -o pipefail
set -x

./consfuzz.py pub_gen -c $CONFIG -t $1 -- $CMD -k @# -o enc.bin @@
./consfuzz.py stage2 -c $CONFIG -n $2 -- $CMD -k @# -o enc.bin @@
./consfuzz.py report -c $CONFIG -b $CMD
batcat $RESULTS/stage3/fuzzing_report.json
