# contrib/pg_mic/Makefile

MODULE_big = pg_mic
OBJS = \
	$(WIN32RES) \
	dml.o \
	enforce.o \
	hooks.o \
	label.o \
	promote.o
EXTENSION = pg_mic
DATA = pg_mic--1.0.sql
PGFILEDESC = "pg_mic - Biba mandatory integrity model"

REGRESS = pg_mic

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = contrib/pg_mic
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif
