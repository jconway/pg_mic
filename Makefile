# contrib/pg_biba/Makefile

MODULE_big = pg_biba
OBJS = \
	$(WIN32RES) \
	dml.o \
	enforce.o \
	hooks.o \
	label.o \
	promote.o
EXTENSION = pg_biba
DATA = pg_biba--1.0.sql
PGFILEDESC = "pg_biba - Biba mandatory integrity model"

REGRESS = pg_biba

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = contrib/pg_biba
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif
