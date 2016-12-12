#####! DO NOT EDIT !#####

# --------------------------------------------------------------------------
# 
# Copyright (c) 2014, NVIDIA Corp.
# All Rights Reserved.
# 
# This is UNPUBLISHED PROPRIETARY SOURCE CODE of NVIDIA Corp.;
# the contents of this file may not be disclosed to third parties, copied or
# duplicated in any form, in whole or in part, without the prior written
# permission of NVIDIA Corp.
# 
# RESTRICTED RIGHTS LEGEND:
# Use, duplication or disclosure by the Government is subject to restrictions
# as set forth in subdivision (c)(1)(ii) of the Rights in Technical Data
# and Computer Software clause at DFARS 252.227-7013, and/or in similar or
# successor clauses in the FAR, DOD or NASA FAR Supplement. Unpublished -
# rights reserved under the Copyright Laws of the United States.
# 
# --------------------------------------------------------------------------
# 
#

DEPTH	:= $(shell depth)
BR_ROOT	:= $(DEPTH)/drv/bootrom

include $(BR_ROOT)/make/Makefile.tools
include $(BR_ROOT)/make/Makefile.defs
include $(BR_ROOT)/make/Makefile.rules

ALIB=lib$(PROJECT)_nvboot_$(shell basename $$PWD).a

TARGETS=$(OUTLIBS)/$(ALIB)

NVBOOT_CFLAGS += -Os
$(TARGETS) : $(OBJS)

all: $(TARGETS)

clean:
	@rm -rf $(PROJECT) $(OUTLIBS)/$(ALIB)

