#!/bin/bash

if [ -z "$1" ]
  then
    echo "Usage: $0 <WINDOW_SZ_1> <WINDOW_SZ_2>"
    exit -1
fi

if [ -z "$2" ]
  then
    echo "Usage: $0 <WINDOW_SZ_1> <WINDOW_SZ_2>"
    exit -1
fi

# Detect where two traces start differing architecturally.
LOG1=dbg1.asm
LOG2=dbg2.asm
ARCH1=dbg1-arch.asm
ARCH2=dbg2-arch.asm
DIFF=diff.asm

set -x

# Create logs
setarch -R /home/alvise/.local/dynamorio/drrun -c ~/.local/dynamorio/libdr_model.so --enable-debug-trace --print-debug-trace --speculator "cond" --max-spec-window $1 -- ls /dev/null 2> $LOG1
setarch -R /home/alvise/.local/dynamorio/drrun -c ~/.local/dynamorio/libdr_model.so --enable-debug-trace --print-debug-trace --speculator "cond" --max-spec-window $2 -- ls /dev/null 2> $LOG2

set +x

# Get the first N lines
#head -n 12000 a1-flush.log > a1-flush-head.log
#head -n 12000 a2-flush.log > a2-flush-head.log

# Compare all the architectural traces
cat $LOG1 | grep ARCH > $ARCH1
cat $LOG2 | grep ARCH > $ARCH2
timeout 10s python3 ../scripts/tracecmp3 $ARCH1 $ARCH2 > $DIFF

# Find the first different entry
grep -m 1 -C 10 "\[93m" $DIFF
first_diff=`grep -m 1 '\[93m' $DIFF | cut -d "]" -f 1 | cut -d "[" -f 3`
last_eq=$((first_diff - 1))


if [ -z "$first_diff" ]
  then
    echo "No diff!"
    exit 0
  else
    echo "Found an architectural diff starting from instruction $first_diff"
fi

# Find corresponding line in each of the logs
L1=$(cat $LOG1 | awk -v line="$last_eq" '/ARCH/{n++; if (n==line)f=1;} f{print NR;f--;}')
L2=$(cat $LOG2 | awk -v line="$last_eq" '/ARCH/{n++; if (n==line)f=1;} f{print NR;f--;}')

echo "vim +$L1 $LOG1"
echo "vim +$L2 $LOG2"
