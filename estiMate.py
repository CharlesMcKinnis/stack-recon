#!/usr/bin/env python2
"""
function estiMate {

# did you give me 2 args?
  if [ -z "$2" ]
  then
    echo "syntax: estiMate CURRENT_MAX PROCESS_NAME"
    return 1
  fi
  MaxClients=$1
  procName=$2
  freeMem=`free|egrep '^Mem:'|awk '{print $4}'`
  ps aux | grep $procName | awk '{
    sum+=$6;line++;if ($6>biggest){biggest=$6} 
  } END {
    print line" '$procName' processes are currently using "sum" KB of memory.";
    print "Average memory per process: "sum/line" KB will use "int((sum/line)*'$MaxClients')" KB if MaxClients is reached.";
    print "Largest process: "biggest" KB will use "biggest*'$MaxClients'" KB if MaxClients is reached.\n"
    print "Based on the largest process, use this as a health check: "int( (('$freeMem'+sum) - (biggest*'$MaxClients')) / biggest )
    print "Positive numbers may mean you can have more clients. Negative numbers mean you are overcommited."
    print "See below for numbers advice.\n"
    print "How many max clients you may be able to handle based on the average size? "(sum+'$freeMem')/(sum/line)
    print "How many max clients you can handle based on largest process and 100% commit? "((sum+'$freeMem')/biggest)
    print "How many max clients you can safely handle based on largest process and 80% commit? "((sum+'$freeMem')/biggest)*.8
  }'
}
"""

