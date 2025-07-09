#!/bin/bash

if [ -z "$1" ] || [ -z "$2" ]; then
  echo "Usage: $0 <STAGE1_TIMEOUT> <STAGE2_N_SECRETS>"
  exit -1
fi

BASE_PATH=/home/alvise/sw-testing/

export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_PATH=$BASE_PATH/AFLplusplus
export SYMCRYPT_PATH=$BASE_PATH/SymCrypt/

CONFIG=consfuzz.yaml
RESULTS=$BASE_PATH/results/latest
CMD=$BASE_PATH/rvzr-sw-eval/drivers/symcrypt/symcrypt
INPUT=$BASE_PATH/rvzr-sw-eval/drivers/symcrypt/test/iv.bin
POLICY_FILE=$BASE_PATH/rvzr-sw-eval/drivers/symcrypt/policy.txt

set -e
set -o pipefail
set -x

./consfuzz.py pub_gen -c $CONFIG -t $1 -- $CMD -d @@ -o enc.bin -p $POLICY_FILE
./consfuzz.py stage2 -c $CONFIG -n $2 -- $CMD -d @@ -o enc.bin -p $POLICY_FILE
./consfuzz.py report -c $CONFIG -b $CMD
batcat $RESULTS/stage3/fuzzing_report.json
