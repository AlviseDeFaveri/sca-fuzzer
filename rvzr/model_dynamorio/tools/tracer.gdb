set logging file gdb.log
set logging on
break main
run
while 1
x/i $pc
stepi
end
quit
