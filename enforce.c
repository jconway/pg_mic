/* -------------------------------------------------------------------------
 *
 * contrib/pg_biba/enforce.c
 *
 * Core Biba integrity check functions.
 *
 * Biba model rules:
 *   No Read Down:  subject_level <= object_level (HIGH cannot read LOW)
 *   No Write Up:   subject_level >= object_level (LOW cannot write HIGH)
 *   UPDATE = both: subject_level == object_level
 *
 * Copyright (c) 2026, PostgreSQL Global Development Group
 *
 * -------------------------------------------------------------------------
 */
#include "postgres.h"

#include "catalog/catalog.h"
#include "catalog/pg_class.h"
#include "miscadmin.h"
#include "pg_biba.h"
#include "utils/lsyscache.h"

/*
 * biba_check_read
 *
 * Enforce "No Read Down": subject_level <= object_level.
 * A HIGH subject cannot read LOW objects.
 */
void
biba_check_read(Oid classId, Oid objectId)
{
	int			subject_level;
	int			object_level;

	/*
	 * Exempt system catalogs from read checks -- otherwise basic SQL
	 * parsing breaks for LOW/MEDIUM users who need to read pg_class,
	 * pg_type, pg_namespace, etc.
	 */
	if (classId == RelationRelationId && IsCatalogRelationOid(objectId))
		return;

	/* System-OID functions are always readable */
	if (objectId < BIBA_SYSTEM_OID_THRESHOLD)
		return;

	subject_level = biba_get_subject_level();
	object_level = biba_get_object_level(classId, objectId);

	/* No Read Down: subject_level <= object_level */
	if (subject_level > object_level)
	{
		if (biba_debug_audit)
			ereport(LOG,
					(errmsg("pg_biba: read denied - subject level %s > object level %s (class %u, object %u)",
							biba_level_to_string(subject_level),
							biba_level_to_string(object_level),
							classId, objectId)));

		if (biba_is_enforcing())
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("pg_biba: read denied - %s integrity subject cannot read %s integrity object",
							biba_level_to_string(subject_level),
							biba_level_to_string(object_level))));
		else
			ereport(WARNING,
					(errmsg("pg_biba: read violation (permissive) - %s integrity subject reading %s integrity object",
							biba_level_to_string(subject_level),
							biba_level_to_string(object_level))));
	}
}

/*
 * biba_check_write
 *
 * Enforce "No Write Up": subject_level >= object_level.
 * A LOW subject cannot write HIGH objects.
 */
void
biba_check_write(Oid classId, Oid objectId)
{
	int			subject_level;
	int			object_level;

	/* System catalogs cannot be written via Biba-controlled paths anyway */
	if (classId == RelationRelationId && IsCatalogRelationOid(objectId))
		return;

	if (objectId < BIBA_SYSTEM_OID_THRESHOLD)
		return;

	subject_level = biba_get_subject_level();
	object_level = biba_get_object_level(classId, objectId);

	/* No Write Up: subject_level >= object_level */
	if (subject_level < object_level)
	{
		if (biba_debug_audit)
			ereport(LOG,
					(errmsg("pg_biba: write denied - subject level %s < object level %s (class %u, object %u)",
							biba_level_to_string(subject_level),
							biba_level_to_string(object_level),
							classId, objectId)));

		if (biba_is_enforcing())
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("pg_biba: write denied - %s integrity subject cannot write %s integrity object",
							biba_level_to_string(subject_level),
							biba_level_to_string(object_level))));
		else
			ereport(WARNING,
					(errmsg("pg_biba: write violation (permissive) - %s integrity subject writing %s integrity object",
							biba_level_to_string(subject_level),
							biba_level_to_string(object_level))));
	}
}

/*
 * biba_check_readwrite
 *
 * Enforce both read and write checks (for UPDATE).
 * Effectively requires subject_level == object_level.
 */
void
biba_check_readwrite(Oid classId, Oid objectId)
{
	biba_check_read(classId, objectId);
	biba_check_write(classId, objectId);
}
