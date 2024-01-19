#!/bin/sh
#

awk '
/^#define/
  {if ($3 != "" && index($2, "(") == 0)
    {print "\t{" $2 ", \""$2"\"},"}
  }
' /usr/include/linux/if_link.h >p.h
