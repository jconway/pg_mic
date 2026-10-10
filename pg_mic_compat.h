/* -------------------------------------------------------------------------
 *
 * contrib/pg_mic/pg_mic_compat.h
 *
 * Isolates PostgreSQL version-divergent APIs (PG14 .. master).
 *
 * Copyright (c) 2026, PostgreSQL Global Development Group
 *
 * -------------------------------------------------------------------------
 */
#ifndef PG_MIC_COMPAT_H
#define PG_MIC_COMPAT_H

#include "postgres.h"
#include "fmgr.h"
#include "access/transam.h"
#include "nodes/parsenodes.h"
#include "nodes/pg_list.h"
#include "utils/acl.h"

StaticAssertDecl(PG_VERSION_NUM >= 140000,
				 "pg_mic requires PostgreSQL 14 or newer");

/* Module magic: PG18+ has the extended form with name/version. */
#if PG_VERSION_NUM >= 180000
#define MIC_MODULE_MAGIC \
	PG_MODULE_MAGIC_EXT(.name = "pg_mic", .version = PG_VERSION)
#else
#define MIC_MODULE_MAGIC PG_MODULE_MAGIC
#endif

typedef struct MicPermEntry
{
	Oid			relid;
	AclMode		requiredPerms;
} MicPermEntry;

/*
 * ExecutorCheckPerms_hook signature differs at PG16: before 16 it is
 * (List *rangeTabls, bool abort); 16+ adds List *rteperminfos.
 */
#if PG_VERSION_NUM >= 160000
#define MIC_CHECKPERMS_PROTO(name) \
	static bool name(List *rangeTabls, List *rteperminfos, bool abort)
#define MIC_PERM_ENTRIES(rangeTabls, rteperminfos) \
	mic_perm_entries((rangeTabls), (rteperminfos))
#define MIC_CALL_NEXT_CHECKPERMS(next, rangeTabls, rteperminfos, abort) \
	(*(next)) ((rangeTabls), (rteperminfos), (abort))
#else
#define MIC_CHECKPERMS_PROTO(name) \
	static bool name(List *rangeTabls, bool abort)
#define MIC_PERM_ENTRIES(rangeTabls, rteperminfos) \
	mic_perm_entries((rangeTabls), NIL)
#define MIC_CALL_NEXT_CHECKPERMS(next, rangeTabls, rteperminfos, abort) \
	(*(next)) ((rangeTabls), (abort))
#endif

/* Defined in dml.c.  Returns List* of MicPermEntry*. */
extern List *mic_perm_entries(List *rangeTabls, List *rteperminfos);

#endif							/* PG_MIC_COMPAT_H */
