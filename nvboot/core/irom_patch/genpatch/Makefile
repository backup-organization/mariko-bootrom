	# RealView Linux-ARM
	#TOOLPATH=/home/aurora/tools/arm/linux/3.0-SP1/bin/
	TOOLPATH=$(HWROOT)/drv/bootrom/tools/arm-tools/bin/
	EXE=
	TARGET_AS=armasm
	TARGET_OBJCOPY=fromelf
	TARGET_LD=armlink
	TARGET_LDFLAGS=
	TARGET_AS_FLAGS=--cpu 7-R --thumb
	TARGET_OBJCOPY_FLAGS=--bin --output $@ $<
	FCODE_SRC=fcode.S

CC=gcc
SRC_OUT=../fcode.h


all: default

default: genpatch$(EXE) fcode.bin

fcode.bin: fcode.o
	$(TOOLPATH)$(TARGET_LD) $(TARGET_LDFLAGS) -o fcode.l $<
	mv fcode.l $<
	$(TOOLPATH)$(TARGET_OBJCOPY) $(TARGET_OBJCOPY_FLAGS)
	genpatch $@ $(GENERR) >$(SRC_OUT)

fcode.o: $(FCODE_SRC)
	$(TOOLPATH)$(TARGET_AS) $(TARGET_AS_FLAGS) -o $@ $<

genpatch$(EXE): genpatch.c
	$(CC) -o $@ $<

clean:
	rm -fr *.bin genpatch$(EXE) *.o $(SRC_OUT)
