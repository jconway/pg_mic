/* -------------------------------------------------------------------------
 *
 * contrib/pg_biba/pg_biba.h
 *
 * Definitions for the Biba mandatory integrity model extension
 *
 * Copyright (c) 2026, PostgreSQL Global Development Group
 *
 * -------------------------------------------------------------------------
 */
#ifndef PG_BIBA_H
#define PG_BIBA_H

#include "catalog/objectaddress.h"
#include "fmgr.h"

/*
 * Provider name used in pg_seclabel / pg_shseclabel
 */
#define BIBA_LABEL_TAG			"biba"

/*
 * Integrity levels
 */
#define BIBA_LEVEL_INVALID		0
#define BIBA_LEVEL_LOW			1
#define BIBA_LEVEL_MEDIUM		2
#define BIBA_LEVEL_HIGH			3

/*
 * Operating modes
 */
#define BIBA_MODE_DISABLED		0
#define BIBA_MODE_PERMISSIVE	1
#define BIBA_MODE_ENFORCING		2

/*
 * FirstNormalObjectId is the threshold for system objects
 */
#define BIBA_SYSTEM_OID_THRESHOLD	16384

/*
 * hooks.c
 */
extern int	biba_mode;
extern bool biba_debug_audit;
extern bool biba_is_enforcing(void);

/*
 * label.c
 */
extern int	biba_level_from_string(const char *label);
extern const char *biba_level_to_string(int level);
extern int	biba_get_subject_level(void);
extern int	biba_get_object_level(Oid classId, Oid objectId);
extern void biba_object_relabel(const ObjectAddress *object,
								const char *seclabel);

/*
 * enforce.c
 */
extern void biba_check_read(Oid classId, Oid objectId);
extern void biba_check_write(Oid classId, Oid objectId);
extern void biba_check_readwrite(Oid classId, Oid objectId);

/*
 * dml.c
 */
extern bool biba_dml_privileges(List *rangeTabls, List *rteperminfos,
								bool abort_on_violation);

/*
 * promote.c -- SQL-callable functions declared via PG_FUNCTION_INFO_V1
 */

#endif							/* PG_BIBA_H */
