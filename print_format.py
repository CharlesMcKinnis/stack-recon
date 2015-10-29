#!/usr/bin/env python2

import sys
from time import sleep

CLR = '\033[2J'
HOME = '\033[H'


table_width = 79
cell_count = 4
cell_width = table_width/cell_count
table_width = cell_width * cell_count # just round it down *shrug*
span_side_to_side = table_width + cell_count + 1
span_inside = table_width + cell_count - 1

sys.stdout.write(CLR)
#sys.stdout.write(HOME)
#moving_num = 101
moving_num = 101
lo_num = 37
hi_num = 433
span_message = str(moving_num)
for moving_num in range(1,500):
    sys.stdout.write(HOME)
    span_message = str(moving_num)
    
    the_range = float(hi_num - lo_num) # this moves the scale so "0" is lo_num, tare wait sort of
    # next, we need to know how far moving num is from tare
    moving_low = float(moving_num - lo_num) # good this far
    
    span_spaces = span_inside - len(span_message)
    inside_width = float(span_inside - len(span_message) - 16) # 16 spaces for margins
    #print "span_spaces %d, inside_width %d" % (span_spaces,inside_width)
    #print "float(moving_low/the_range): %f" % (moving_low/the_range)
    #print "int(inside_width*float(moving_low/the_range)) %d" % int(inside_width*(moving_low/the_range))
    #print "int((span_spaces-inside_width)/2) %d" % int((span_spaces-inside_width)/2)
    right_space = int(inside_width*(moving_low/the_range)) + int((span_spaces-inside_width)/2)
    left_space = int(inside_width) - right_space + int((span_spaces-inside_width)/2) + 8
    if right_space > span_spaces:
        right_space = span_spaces
    if left_space > span_spaces:
        left_space = span_spaces
    #print "left %d, right %d" % (left_space,right_space)

    rows=[]
    rows.append(["avg 100% danger","avg 80% warning","lrg 100% cautious","lrg 80% safe"])
    rows.append(["433","255","66","37"])
    
    sys.stdout.write(("+%s" % ("-"*cell_width)*cell_count)+"+\n")
    for row in rows:
        sys.stdout.write("|")
        for cell in row:
            text_sz = len(cell)
            spaces = cell_width - text_sz
            spaces_before = spaces / 2
            spaces_after = spaces - spaces_before # just in case there is an odd number
            sys.stdout.write("%s%s%s" % (" " * spaces_before, cell, " " * spaces_after))
            sys.stdout.write("|")
        sys.stdout.write("\n")
    #                   CELL--------------CELL * COUNT +      CLOSE
    sys.stdout.write( ( ("+"+("-"*cell_width)) * cell_count)+"+\n") # solid line divider
    sys.stdout.write("|")
    sys.stdout.write(" "*left_space)
    sys.stdout.write(span_message)
    sys.stdout.write(" "*right_space)
    sys.stdout.write("|\n")
    
    """
    span_side_to_side = table_width+cell_count+1 #-2
    print "*" * span_side_to_side
    sys.stdout.write("|"+(((" "*cell_width)+" ")*(cell_count-1))+(" "*cell_width)+"|\n") #span
    #sys.stdout.write("|"+(((" "*cell_width)+"|")*(cell_count-1))+(" "*cell_width)+"|\n") #virt bar only, no Horizontal bar
    sys.stdout.write( ( ("+"+("-"*cell_width)) * cell_count)+"+\n") # solid line divider
    """
    sys.stdout.write( ( ("+"+("-"*cell_width)) * cell_count)+"+\n") # solid line divider
    sleep(.025)
