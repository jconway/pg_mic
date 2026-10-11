/* -------------------------------------------------------------------------
 *
 * contrib/pg_mic/label.c
 *
 * Label provider: level conversion, subject/object level resolution,
 * and relabel validation for the Biba integrity model.
 *
 * Copyright (c) 2026, PostgreSQL Global Development Group
 *
 * -------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/htup_details.h"
#include "access/table.h"
#include "catalog/indexing.h"
#include "catalog/pg_authid.h"
#include "catalog/pg_class.h"
#include "catalog/pg_proc.h"
#include "commands/seclabel.h"
#include "miscadmin.h"
#include "pg_mic.h"
#include "utils/builtins.h"
#include "utils/syscache.h"

/*
 * Whether a function needs the function-manager hook is decided from its
 * label when its FmgrInfo is built, and the planner declines to inline any
 * function that needs it.  A function labeled HIGH needs no hook (no subject
 * can be above it), so HIGH SQL functions inline normally.  Relabeling a
 * function must therefore invalidate every cached plan that depends on it,
 * or a plan built while it was HIGH would keep calling (or keep an inlined
 * copy of) a function that has since been demoted.  A security label change
 * touches only pg_seclabel, which no cache watches, so rewrite the pg_proc
 * row in place: that broadcasts the PROCOID invalidation the plan cache
 * listens for.
 */
static void
mic_invalidate_function(Oid funcid)
{
	Relation	rel;
	HeapTuple	tup;

	rel = table_open(ProcedureRelationId, RowExclusiveLock);
	tup = SearchSysCacheCopy1(PROCOID, ObjectIdGetDatum(funcid));
	if (HeapTupleIsValid(tup))
	{
		CatalogTupleUpdate(rel, &tup->t_self, tup);
		heap_freetuple(tup);
	}
	table_close(rel, RowExclusiveLock);
}

/*
 * Set an integrity label.  All of the extension's own relabeling goes
 * through here so that function relabels invalidate dependent plans.
 */
void
mic_set_label(const ObjectAddress *object, const char *label)
{
	if (object->classId == ProcedureRelationId && object->objectSubId == 0)
		mic_invalidate_function(object->objectId);
	SetSecurityLabel(object, MIC_LABEL_TAG, label);
}

/*
 * Convert a string label to an integrity level value.
 * Returns MIC_LEVEL_INVALID if the label is not recognized.
 */
int
mic_level_from_string(const char *label)
{
	if (label == NULL)
		return MIC_LEVEL_INVALID;

	if (pg_strcasecmp(label, "low") == 0)
		return MIC_LEVEL_LOW;
	if (pg_strcasecmp(label, "medium") == 0)
		return MIC_LEVEL_MEDIUM;
	if (pg_strcasecmp(label, "high") == 0)
		return MIC_LEVEL_HIGH;

	return MIC_LEVEL_INVALID;
}

/*
 * Convert an integrity level value to its canonical string label.
 */
const char *
mic_level_to_string(int level)
{
	switch (level)
	{
		case MIC_LEVEL_LOW:
			return "low";
		case MIC_LEVEL_MEDIUM:
			return "medium";
		case MIC_LEVEL_HIGH:
			return "high";
		default:
			return "unknown";
	}
}

/*
 * Determine the integrity level of the current session (subject).
 *
 * - Superuser => HIGH
 * - Labeled role => label value
 * - Unlabeled role => LOW
 */
int
mic_get_subject_level(void)
{
	ObjectAddress object;
	char	   *label;
	int			level;

	if (superuser())
		return MIC_LEVEL_HIGH;

	object.classId = AuthIdRelationId;
	object.objectId = GetUserId();
	object.objectSubId = 0;

	label = GetSecurityLabel(&object, MIC_LABEL_TAG);
	if (label == NULL)
		return MIC_LEVEL_LOW;

	level = mic_level_from_string(label);
	pfree(label);

	return (level != MIC_LEVEL_INVALID) ? level : MIC_LEVEL_LOW;
}

/*
 * Determine the integrity level of a database object.
 *
 * - System object (OID < 16384) => HIGH
 * - Labeled object => label value
 * - Unlabeled object => LOW
 */
int
mic_get_object_level(Oid classId, Oid objectId)
{
	ObjectAddress object;
	char	   *label;
	int			level;

	/* System objects are implicitly HIGH integrity */
	if (objectId < MIC_SYSTEM_OID_THRESHOLD)
		return MIC_LEVEL_HIGH;

	object.classId = classId;
	object.objectId = objectId;
	object.objectSubId = 0;

	label = GetSecurityLabel(&object, MIC_LABEL_TAG);
	if (label == NULL)
		return MIC_LEVEL_LOW;

	level = mic_level_from_string(label);
	pfree(label);

	return (level != MIC_LEVEL_INVALID) ? level : MIC_LEVEL_LOW;
}

/*
 * mic_object_relabel
 *
 * Validation hook for SECURITY LABEL FOR mic ON ... IS '...';
 * Called by the security label infrastructure before applying the label.
 */
void
mic_object_relabel(const ObjectAddress *object, const char *seclabel)
{
	/* NULL means "remove the label" -- always allowed for superuser */
	if (seclabel == NULL)
	{
		if (!superuser())
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("pg_mic: only superuser can remove integrity labels")));
		return;
	}

	/* Validate the label string */
	if (mic_level_from_string(seclabel) == MIC_LEVEL_INVALID)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_NAME),
				 errmsg("pg_mic: \"%s\" is not a valid integrity level", seclabel),
				 errhint("Valid levels are: low, medium, high.")));

	/* Only superuser can set integrity labels */
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("pg_mic: only superuser can set integrity labels")));

	/* SECURITY LABEL ... ON FUNCTION: the label is applied by the caller */
	if (object->classId == ProcedureRelationId && object->objectSubId == 0)
		mic_invalidate_function(object->objectId);
}
