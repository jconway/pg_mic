/* -------------------------------------------------------------------------
 *
 * contrib/pg_mic/pg_mic.h
 *
 * Definitions for the Biba mandatory integrity model extension
 *
 * Copyright (c) 2026, PostgreSQL Global Development Group
 *
 * -------------------------------------------------------------------------
 */
#ifndef PG_MIC_H
#define PG_MIC_H

#include "catalog/objectaddress.h"
#include "fmgr.h"
#include "nodes/nodes.h"
#include "utils/acl.h"

/*
 * Provider name used in pg_seclabel / pg_shseclabel
 */
#define MIC_LABEL_TAG			"mic"

/*
 * Integrity levels
 */
#define MIC_LEVEL_INVALID		0
#define MIC_LEVEL_LOW			1
#define MIC_LEVEL_MEDIUM		2
#define MIC_LEVEL_HIGH			3

/*
 * Operating modes
 */
#define MIC_MODE_DISABLED		0
#define MIC_MODE_PERMISSIVE	1
#define MIC_MODE_ENFORCING		2

/*
 * FirstNormalObjectId is the threshold for system objects
 */
#define MIC_SYSTEM_OID_THRESHOLD	16384

/*
 * hooks.c
 */
extern int	mic_mode;
extern bool mic_debug_audit;
extern bool mic_is_enforcing(void);

/*
 * label.c
 */
extern int	mic_level_from_string(const char *label);
extern const char *mic_level_to_string(int level);
extern int	mic_get_subject_level(void);
extern int	mic_get_role_level_oid(Oid roleid);
extern int	mic_get_object_level(Oid classId, Oid objectId);
extern void mic_object_relabel(const ObjectAddress *object,
								const char *seclabel);
extern void mic_set_label(const ObjectAddress *object, const char *label);

/*
 * enforce.c
 */
extern void mic_check_read(Oid classId, Oid objectId);
extern void mic_check_write(Oid classId, Oid objectId);
extern void mic_check_readwrite(Oid classId, Oid objectId);

/*
 * dml.c
 */
extern bool mic_dml_privileges(List *perm_entries, bool abort_on_violation);

/*
 * reach.c
 */
extern void mic_check_reachable_functions(Oid relid, AclMode required_ops);
extern void mic_check_truncate_triggers(List *relids, bool cascade);
extern void mic_check_reindex_exprs(Oid relid, bool is_index);
extern void mic_check_reindex_relations(Oid nspoid, bool stats);
extern void mic_check_stats_exprs(Oid relid);
extern void mic_check_rules(Oid relid, AclMode required_ops);
extern void mic_check_matview_refresh(Oid relid);
extern List *mic_relation_tree(Oid relid, bool inh);
extern void mic_check_expr_functions(Node *expr, int subject_level,
									  const char *via, const char *objname);
extern void mic_check_one_function(Oid funcid, int subject_level,
									const char *via, const char *objname);
extern void mic_check_one_operator(Oid opno, int subject_level,
									const char *via, const char *objname);
extern void mic_check_function_call(Oid funcid);
extern void mic_check_column_type(Oid typid, int subject_level,
								  const char *objname);

/*
 * promote.c -- SQL-callable functions declared via PG_FUNCTION_INFO_V1
 */

#endif							/* PG_MIC_H */
