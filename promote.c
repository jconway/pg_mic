/* -------------------------------------------------------------------------
 *
 * contrib/pg_biba/promote.c
 *
 * SQL-callable administration and introspection functions for the
 * Biba integrity model.
 *
 * Copyright (c) 2026, PostgreSQL Global Development Group
 *
 * -------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/heapam.h"
#include "access/htup_details.h"
#include "access/table.h"
#include "access/tableam.h"
#include "catalog/namespace.h"
#include "catalog/pg_authid.h"
#include "catalog/pg_class.h"
#include "commands/seclabel.h"
#include "funcapi.h"
#include "miscadmin.h"
#include "pg_biba.h"
#include "utils/acl.h"
#include "utils/builtins.h"
#include "utils/regproc.h"
#include "utils/rel.h"
#include "utils/varlena.h"

PG_FUNCTION_INFO_V1(biba_get_session_level);
PG_FUNCTION_INFO_V1(biba_get_role_level);
PG_FUNCTION_INFO_V1(biba_get_table_level);
PG_FUNCTION_INFO_V1(biba_set_role_level);
PG_FUNCTION_INFO_V1(biba_promote_table);
PG_FUNCTION_INFO_V1(biba_promote_object);
PG_FUNCTION_INFO_V1(biba_initialize_labels);

/*
 * biba_get_session_level() -- return current user's integrity level
 */
Datum
biba_get_session_level(PG_FUNCTION_ARGS)
{
	PG_RETURN_TEXT_P(cstring_to_text(biba_level_to_string(biba_get_subject_level())));
}

/*
 * biba_get_role_level(role_name text) -- return any role's integrity level
 */
Datum
biba_get_role_level(PG_FUNCTION_ARGS)
{
	text	   *role_text = PG_GETARG_TEXT_PP(0);
	char	   *role_name = text_to_cstring(role_text);
	Oid			role_oid;
	int			level;

	role_oid = get_role_oid(role_name, false);
	level = biba_get_object_level(AuthIdRelationId, role_oid);

	PG_RETURN_TEXT_P(cstring_to_text(biba_level_to_string(level)));
}

/*
 * biba_get_table_level(table_name text) -- return a table's integrity level
 */
Datum
biba_get_table_level(PG_FUNCTION_ARGS)
{
	text	   *table_text = PG_GETARG_TEXT_PP(0);
	RangeVar   *rv;
	Oid			rel_oid;
	int			level;

	rv = makeRangeVarFromNameList(textToQualifiedNameList(table_text));
	rel_oid = RangeVarGetRelid(rv, NoLock, false);
	level = biba_get_object_level(RelationRelationId, rel_oid);

	PG_RETURN_TEXT_P(cstring_to_text(biba_level_to_string(level)));
}

/*
 * biba_set_role_level(role_name text, level text) -- superuser only
 */
Datum
biba_set_role_level(PG_FUNCTION_ARGS)
{
	text	   *role_text = PG_GETARG_TEXT_PP(0);
	text	   *level_text = PG_GETARG_TEXT_PP(1);
	char	   *role_name = text_to_cstring(role_text);
	char	   *level_str = text_to_cstring(level_text);
	Oid			role_oid;
	ObjectAddress object;

	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("pg_biba: only superuser can set role integrity levels")));

	if (biba_level_from_string(level_str) == BIBA_LEVEL_INVALID)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("pg_biba: \"%s\" is not a valid integrity level", level_str),
				 errhint("Valid levels are: low, medium, high.")));

	role_oid = get_role_oid(role_name, false);

	object.classId = AuthIdRelationId;
	object.objectId = role_oid;
	object.objectSubId = 0;

	SetSecurityLabel(&object, BIBA_LABEL_TAG, level_str);

	PG_RETURN_VOID();
}

/*
 * biba_promote_table(table_name text, new_level text) -- superuser only
 */
Datum
biba_promote_table(PG_FUNCTION_ARGS)
{
	text	   *table_text = PG_GETARG_TEXT_PP(0);
	text	   *level_text = PG_GETARG_TEXT_PP(1);
	char	   *level_str = text_to_cstring(level_text);
	RangeVar   *rv;
	Oid			rel_oid;
	ObjectAddress object;

	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("pg_biba: only superuser can promote table integrity levels")));

	if (biba_level_from_string(level_str) == BIBA_LEVEL_INVALID)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("pg_biba: \"%s\" is not a valid integrity level", level_str),
				 errhint("Valid levels are: low, medium, high.")));

	rv = makeRangeVarFromNameList(textToQualifiedNameList(table_text));
	rel_oid = RangeVarGetRelid(rv, NoLock, false);

	object.classId = RelationRelationId;
	object.objectId = rel_oid;
	object.objectSubId = 0;

	SetSecurityLabel(&object, BIBA_LABEL_TAG, level_str);

	PG_RETURN_VOID();
}

/*
 * biba_promote_object(class_id oid, object_id oid, new_level text)
 * -- superuser only, generic object promotion
 */
Datum
biba_promote_object(PG_FUNCTION_ARGS)
{
	Oid			class_id = PG_GETARG_OID(0);
	Oid			object_id = PG_GETARG_OID(1);
	text	   *level_text = PG_GETARG_TEXT_PP(2);
	char	   *level_str = text_to_cstring(level_text);
	ObjectAddress object;

	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("pg_biba: only superuser can promote object integrity levels")));

	if (biba_level_from_string(level_str) == BIBA_LEVEL_INVALID)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("pg_biba: \"%s\" is not a valid integrity level", level_str),
				 errhint("Valid levels are: low, medium, high.")));

	object.classId = class_id;
	object.objectId = object_id;
	object.objectSubId = 0;

	SetSecurityLabel(&object, BIBA_LABEL_TAG, level_str);

	PG_RETURN_VOID();
}

/*
 * biba_initialize_labels() -- label all existing user tables at the
 * caller's integrity level.  Superuser only.
 */
Datum
biba_initialize_labels(PG_FUNCTION_ARGS)
{
	const char *level_str;
	Relation	pg_class;
	TableScanDesc scan;
	HeapTuple	tuple;

	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("pg_biba: only superuser can initialize labels")));

	level_str = biba_level_to_string(biba_get_subject_level());

	pg_class = table_open(RelationRelationId, AccessShareLock);
	scan = table_beginscan_catalog(pg_class, 0, NULL);

	while ((tuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
	{
		Form_pg_class classForm = (Form_pg_class) GETSTRUCT(tuple);
		Oid			relOid = classForm->oid;
		ObjectAddress object;
		char	   *existing;

		/* Skip system objects */
		if (relOid < BIBA_SYSTEM_OID_THRESHOLD)
			continue;

		/* Only label regular tables, partitioned tables, and views */
		if (classForm->relkind != RELKIND_RELATION &&
			classForm->relkind != RELKIND_PARTITIONED_TABLE &&
			classForm->relkind != RELKIND_VIEW &&
			classForm->relkind != RELKIND_MATVIEW)
			continue;

		/* Skip if already labeled */
		object.classId = RelationRelationId;
		object.objectId = relOid;
		object.objectSubId = 0;

		existing = GetSecurityLabel(&object, BIBA_LABEL_TAG);
		if (existing != NULL)
		{
			pfree(existing);
			continue;
		}

		SetSecurityLabel(&object, BIBA_LABEL_TAG, level_str);
	}

	table_endscan(scan);
	table_close(pg_class, AccessShareLock);

	PG_RETURN_VOID();
}
