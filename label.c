/* -------------------------------------------------------------------------
 *
 * contrib/pg_biba/label.c
 *
 * Label provider: level conversion, subject/object level resolution,
 * and relabel validation for the Biba integrity model.
 *
 * Copyright (c) 2026, PostgreSQL Global Development Group
 *
 * -------------------------------------------------------------------------
 */
#include "postgres.h"

#include "catalog/pg_authid.h"
#include "catalog/pg_class.h"
#include "commands/seclabel.h"
#include "miscadmin.h"
#include "pg_biba.h"
#include "utils/builtins.h"

/*
 * Convert a string label to an integrity level value.
 * Returns BIBA_LEVEL_INVALID if the label is not recognized.
 */
int
biba_level_from_string(const char *label)
{
	if (label == NULL)
		return BIBA_LEVEL_INVALID;

	if (pg_strcasecmp(label, "low") == 0)
		return BIBA_LEVEL_LOW;
	if (pg_strcasecmp(label, "medium") == 0)
		return BIBA_LEVEL_MEDIUM;
	if (pg_strcasecmp(label, "high") == 0)
		return BIBA_LEVEL_HIGH;

	return BIBA_LEVEL_INVALID;
}

/*
 * Convert an integrity level value to its canonical string label.
 */
const char *
biba_level_to_string(int level)
{
	switch (level)
	{
		case BIBA_LEVEL_LOW:
			return "low";
		case BIBA_LEVEL_MEDIUM:
			return "medium";
		case BIBA_LEVEL_HIGH:
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
biba_get_subject_level(void)
{
	ObjectAddress object;
	char	   *label;
	int			level;

	if (superuser())
		return BIBA_LEVEL_HIGH;

	object.classId = AuthIdRelationId;
	object.objectId = GetUserId();
	object.objectSubId = 0;

	label = GetSecurityLabel(&object, BIBA_LABEL_TAG);
	if (label == NULL)
		return BIBA_LEVEL_LOW;

	level = biba_level_from_string(label);
	pfree(label);

	return (level != BIBA_LEVEL_INVALID) ? level : BIBA_LEVEL_LOW;
}

/*
 * Determine the integrity level of a database object.
 *
 * - System object (OID < 16384) => HIGH
 * - Labeled object => label value
 * - Unlabeled object => LOW
 */
int
biba_get_object_level(Oid classId, Oid objectId)
{
	ObjectAddress object;
	char	   *label;
	int			level;

	/* System objects are implicitly HIGH integrity */
	if (objectId < BIBA_SYSTEM_OID_THRESHOLD)
		return BIBA_LEVEL_HIGH;

	object.classId = classId;
	object.objectId = objectId;
	object.objectSubId = 0;

	label = GetSecurityLabel(&object, BIBA_LABEL_TAG);
	if (label == NULL)
		return BIBA_LEVEL_LOW;

	level = biba_level_from_string(label);
	pfree(label);

	return (level != BIBA_LEVEL_INVALID) ? level : BIBA_LEVEL_LOW;
}

/*
 * biba_object_relabel
 *
 * Validation hook for SECURITY LABEL FOR biba ON ... IS '...';
 * Called by the security label infrastructure before applying the label.
 */
void
biba_object_relabel(const ObjectAddress *object, const char *seclabel)
{
	/* NULL means "remove the label" -- always allowed for superuser */
	if (seclabel == NULL)
	{
		if (!superuser())
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("pg_biba: only superuser can remove integrity labels")));
		return;
	}

	/* Validate the label string */
	if (biba_level_from_string(seclabel) == BIBA_LEVEL_INVALID)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_NAME),
				 errmsg("pg_biba: \"%s\" is not a valid integrity level", seclabel),
				 errhint("Valid levels are: low, medium, high.")));

	/* Only superuser can set integrity labels */
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("pg_biba: only superuser can set integrity labels")));
}
