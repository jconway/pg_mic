/* -------------------------------------------------------------------------
 *
 * contrib/pg_mic/enforce.c
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
#include "pg_mic.h"
#include "utils/lsyscache.h"

/*
 * mic_check_read
 *
 * Enforce "No Read Down": subject_level <= object_level.
 * A HIGH subject cannot read LOW objects.
 */
void
mic_check_read(Oid classId, Oid objectId)
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
	if (objectId < MIC_SYSTEM_OID_THRESHOLD)
		return;

	subject_level = mic_get_subject_level();
	object_level = mic_get_object_level(classId, objectId);

	/* No Read Down: subject_level <= object_level */
	if (subject_level > object_level)
	{
		if (mic_debug_audit)
			ereport(LOG,
					(errmsg("pg_mic: read denied - subject level %s > object level %s (class %u, object %u)",
							mic_level_to_string(subject_level),
							mic_level_to_string(object_level),
							classId, objectId)));

		if (mic_is_enforcing())
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("pg_mic: read denied - %s integrity subject cannot read %s integrity object",
							mic_level_to_string(subject_level),
							mic_level_to_string(object_level))));
		else
			ereport(WARNING,
					(errmsg("pg_mic: read violation (permissive) - %s integrity subject reading %s integrity object",
							mic_level_to_string(subject_level),
							mic_level_to_string(object_level))));
	}
}

/*
 * mic_check_write
 *
 * Enforce "No Write Up": subject_level >= object_level.
 * A LOW subject cannot write HIGH objects.
 */
void
mic_check_write(Oid classId, Oid objectId)
{
	int			subject_level;
	int			object_level;

	/* System catalogs cannot be written via Biba-controlled paths anyway */
	if (classId == RelationRelationId && IsCatalogRelationOid(objectId))
		return;

	if (objectId < MIC_SYSTEM_OID_THRESHOLD)
		return;

	subject_level = mic_get_subject_level();
	object_level = mic_get_object_level(classId, objectId);

	/* No Write Up: subject_level >= object_level */
	if (subject_level < object_level)
	{
		if (mic_debug_audit)
			ereport(LOG,
					(errmsg("pg_mic: write denied - subject level %s < object level %s (class %u, object %u)",
							mic_level_to_string(subject_level),
							mic_level_to_string(object_level),
							classId, objectId)));

		if (mic_is_enforcing())
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("pg_mic: write denied - %s integrity subject cannot write %s integrity object",
							mic_level_to_string(subject_level),
							mic_level_to_string(object_level))));
		else
			ereport(WARNING,
					(errmsg("pg_mic: write violation (permissive) - %s integrity subject writing %s integrity object",
							mic_level_to_string(subject_level),
							mic_level_to_string(object_level))));
	}
}

/*
 * mic_check_readwrite
 *
 * Enforce both read and write checks (for UPDATE).
 * Effectively requires subject_level == object_level.
 */
void
mic_check_readwrite(Oid classId, Oid objectId)
{
	mic_check_read(classId, objectId);
	mic_check_write(classId, objectId);
}
