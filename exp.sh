#!/bin/bash
set -x

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
LOG1=a1-flush.log
LOG2=a2-flush.log
ARCH1=a1-arch.log
ARCH2=a2-arch.log
DIFF=a12-arch-diff.log

# Create logs
setarch -R /home/alvise/.local/dynamorio//DynamoRIO-Linux-11.2.0/bin64/drrun -debug -c ~/.local/dynamorio/libdr_model.so --speculator "cond" --max-spec-window $1 -- ls /dev/null > $LOG1 2>&1
setarch -R /home/alvise/.local/dynamorio//DynamoRIO-Linux-11.2.0/bin64/drrun -debug -c ~/.local/dynamorio/libdr_model.so --speculator "cond" --max-spec-window $2 -- ls /dev/null > $LOG2 2>&1

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

# Find corresponding line in each of the logs
L1=$(cat $LOG1 | awk -v line="$last_eq" '/ARCH/{n++; if (n==line)f=1;} f{print NR;f--;}')
L2=$(cat $LOG2 | awk -v line="$last_eq" '/ARCH/{n++; if (n==line)f=1;} f{print NR;f--;}')

echo "vim +$L1 $LOG1"
echo "vim +$L2 $LOG2"
