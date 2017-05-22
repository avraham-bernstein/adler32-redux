################################################################################
# FILE: Makefile
# DESCRIP: Makefile for the Adler32-Redux project.
# TEST ENV: Ubuntu 16.04, gcc/clang
# DATE: 2017-05-22T11:37:00Z
# AUTHOR: Avraham DOT Bernstein AT gmail
# COPYRIGHT (c) 2017 Avraham Bernstein, Jerusalem ISRAEL. All rights reserved.
#UTHOR: Avraham DOT Bernstein AT gmail
# COPYRIGHT (c) 2017 Avraham Bernstein, Jerusalem ISRAEL. All rights reserved.
# LICENSE: Apache License, Version 2.0: https://opensource.org/licenses/Apache-2.0
#  The details specified in the above license link are what is legally binding.
#  But in plain English, I have placed this software in the public domain.
#  Use it any way you like, as long as you give me attribution. If you have any
#  comments or suggestions, or find or fix any bugs, then please contact me.
#  CAVEAT EMPTOR! This is an evolving prototype designed for illustrative
#  purposes. I am providing it to you for free AS IS with absolutely NO
#  GUARANTEE OF MERCHANTABILITY and NO GUARANTEE OF FITNESS FOR ANY PURPOSE.
#  If you would like me to provide you with an industrial strength version with
#  a commercial guarantee then please contact me.
# REVISIONS:
#    a commercial guarantee then please contact me.
# REVISIONS:
# 2017-05-22: 1.0.0: AB: original
################################################################################

.SUFFIXES :

.DEFAULT_GOAL := all

CC := gcc
CFLAGS := -Wall

DEBUG_FLAGS := -g -O0
CLANG_FLAGS := -Wno-tautological-pointer-compare

ifdef DEBUG
CFLAGS += $(DEBUG_FLAGS)
endif

ifdef NDEBUG
CFLAGS += -DNDEBUG
endif

ifeq ($(CC),clang)
CFLAGS += $(CLANG_FLAGS)
endif

MAIN := ayb-adler-test
TARGETS := ayb-adler.o $(MAIN)

ifdef TEST
TARGET := $(MAIN)
else
TARGET := ayb-adler.o
endif

all: $(TARGET)

clean:
	rm -f $(TARGETS)

%.o : %.c
	$(CC) $(CFLAGS) -o $@ -c $<

$(MAIN) : ayb-adler.c
	$(CC) $(CFLAGS) -o $@ -DTEST $^
