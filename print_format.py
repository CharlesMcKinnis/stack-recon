#!/usr/bin/env python2

import sys
from time import sleep

def print_table(rows, table_width, **kwargs):
    #notop = True to omit the bar at the top of the table

    # print the top bar
    #if not "notop" in kwargs:
    #    sys.stdout.write(("+%s" % ("-"*cell_width)*cell_count)+"+\n")

    row_counter = 0
    total_rows = len(rows)
    for row in rows:
        row_counter += 1
        cell_count = len(row)
        cell_width = table_width/cell_count
        left_over = cell_width % cell_count
        # minus 1 to account for the | bar divider
        cell_width = cell_width - 1
        cell_counter = 1
        print "table W %d, cell W %d, LO %d" % (table_width,cell_width,left_over)
        if row_counter == 1 and not "notop" in kwargs:
            sys.stdout.write(("+%s" % ("-"*cell_width)*cell_count)+"+\n")

        cells_width = []
        sys.stdout.write("|")
        for cell in row:
            text_sz = len(cell)
            spaces = cell_width - text_sz
            if cell_counter <= left_over:
                spaces += 1
                cells_width.append(cell_width+1)
            else:
                cells_width.append(cell_width)
            
            spaces_before = spaces / 2
            # sometimes, the table width doesn't divide equally
            # the modulo is stored as left_over, and that many cells need a spare space
            cell_counter += 1
            
            spaces_after = spaces - spaces_before # just in case there is an odd number
            sys.stdout.write("%s%s%s" % (" " * spaces_before, cell, " " * spaces_after))
            sys.stdout.write("|")
        #row level
        sys.stdout.write("\n")
        
        # print the underline
        # if it is the last row, print it too, unless you set nobottom
        if (row_counter == total_rows and not "nobottom" in kwargs) or row_counter != total_rows:
            for one in cells_width:
                sys.stdout.write("+")
                sys.stdout.write("-"*one)
            sys.stdout.write("+\n")
            print cells_width
    #table level
table_width = 79

#rows=[]
#rows.append(["avg proc size","largest process size"])
#print_table(rows, 80, notop=True)

rows=[]
#rows.append(["avg 100% danger","avg 80% warning","lrg 100% cautious","lrg 80% safe"])
rows.append(["avg proc size","largest process size"])
rows.append(["433","255","66"])
rows.append(["433","255","66","37"])
rows.append(["433","255","66","37","12"])
rows.append(["433","255","66","37","12","5"])
rows.append(["433","255","66","37","12","5","54"])
print_table(rows, 80)
