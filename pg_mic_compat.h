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
#include "optimizer/planner.h"
#include "miscadmin.h"
#include "utils/acl.h"

StaticAssertDecl(PG_VERSION_NUM >= 140000,
				 "pg_mic requires PostgreSQL 14 or newer");

/* Module magic: PG18+ has the extended form with name/version. */
#if PG_VERSION_NUM >= 180000
#define MIC_MODULE_MAGIC \
	PG_MODULE_MAGIC_EXT(.name = "pg_mic", .version = PG_VERSION)
#else
#define MIC_MODULE_MAGIC PG_MODULE_MAGIC
/* fmgr.h declares _PG_init only from PG18 on; avoid -Wmissing-prototypes */
extern PGDLLEXPORT void _PG_init(void);
#endif

typedef struct MicPermEntry
{
	Oid			relid;
	AclMode		requiredPerms;
	bool		inh;			/* statement reaches inheritance children */
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

/* MarkGUCPrefixReserved() replaced EmitWarningsOnPlaceholders() in PG15. */
#if PG_VERSION_NUM >= 150000
#define MIC_MARK_GUC_PREFIX_RESERVED(prefix) MarkGUCPrefixReserved(prefix)
#else
#define MIC_MARK_GUC_PREFIX_RESERVED(prefix) EmitWarningsOnPlaceholders(prefix)
#endif

/*
 * FuncnameGetCandidates() gained a trailing int *fgc_flags argument in PG19.
 */
#if PG_VERSION_NUM >= 190000
#define MIC_FUNCNAME_GET_CANDIDATES(names) \
	FuncnameGetCandidates((names), -1, NIL, false, false, false, true, \
						  &fgc_flags)
#else
#define MIC_FUNCNAME_GET_CANDIDATES(names) \
	FuncnameGetCandidates((names), -1, NIL, false, false, false, true)
#endif

/*
 * planner_hook gained a trailing ExplainState *es argument in PG19.
 */
#if PG_VERSION_NUM >= 190000
#define MIC_PLANNER_PROTO(name) \
	static PlannedStmt *name(Query *parse, const char *query_string, \
							 int cursorOptions, ParamListInfo boundParams, \
							 ExplainState *es)
#define MIC_CALL_PLANNER(fn) \
	(*(fn)) (parse, query_string, cursorOptions, boundParams, es)
#else
#define MIC_PLANNER_PROTO(name) \
	static PlannedStmt *name(Query *parse, const char *query_string, \
							 int cursorOptions, ParamListInfo boundParams)
#define MIC_CALL_PLANNER(fn) \
	(*(fn)) (parse, query_string, cursorOptions, boundParams)
#endif

/* IsAutoVacuumWorkerProcess() became AmAutoVacuumWorkerProcess() in PG17. */
#if PG_VERSION_NUM >= 170000
#define MIC_AM_AUTOVACUUM_WORKER() AmAutoVacuumWorkerProcess()
#else
#include "postmaster/autovacuum.h"
#define MIC_AM_AUTOVACUUM_WORKER() IsAutoVacuumWorkerProcess()
#endif

/* Defined in dml.c.  Returns List* of MicPermEntry*. */
extern List *mic_perm_entries(List *rangeTabls, List *rteperminfos);

#endif							/* PG_MIC_COMPAT_H */
