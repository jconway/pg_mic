/* -------------------------------------------------------------------------
 *
 * contrib/pg_mic/promote.c
 *
 * SQL-callable administration and introspection functions for the
 * Biba integrity model.
 *
 * Copyright (c) 2026, PostgreSQL Global Development Group
 *
 * -------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/genam.h"
#include "access/heapam.h"
#include "access/htup_details.h"
#include "access/table.h"
#include "access/tableam.h"
#include "catalog/namespace.h"
#include "catalog/dependency.h"
#include "catalog/pg_authid.h"
#include "catalog/pg_class.h"
#include "catalog/pg_depend.h"
#include "catalog/pg_extension.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_type.h"
#include "commands/extension.h"
#include "commands/seclabel.h"
#include "funcapi.h"
#include "miscadmin.h"
#include "pg_mic.h"
#include "utils/acl.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/regproc.h"
#include "utils/rel.h"
#include "utils/varlena.h"

PG_FUNCTION_INFO_V1(mic_get_session_level);
PG_FUNCTION_INFO_V1(mic_get_role_level);
PG_FUNCTION_INFO_V1(mic_get_table_level);
PG_FUNCTION_INFO_V1(mic_set_role_level);
PG_FUNCTION_INFO_V1(mic_promote_table);
PG_FUNCTION_INFO_V1(mic_promote_object);
PG_FUNCTION_INFO_V1(mic_initialize_labels);
PG_FUNCTION_INFO_V1(mic_promote_extension);

/*
 * mic_get_session_level() -- return current user's integrity level
 */
Datum
mic_get_session_level(PG_FUNCTION_ARGS)
{
	PG_RETURN_TEXT_P(cstring_to_text(mic_level_to_string(mic_get_subject_level())));
}

/*
 * mic_get_role_level(role_name text) -- return any role's integrity level
 */
Datum
mic_get_role_level(PG_FUNCTION_ARGS)
{
	text	   *role_text = PG_GETARG_TEXT_PP(0);
	char	   *role_name = text_to_cstring(role_text);
	Oid			role_oid;
	int			level;

	role_oid = get_role_oid(role_name, false);
	level = mic_get_object_level(AuthIdRelationId, role_oid);

	PG_RETURN_TEXT_P(cstring_to_text(mic_level_to_string(level)));
}

/*
 * mic_get_table_level(table_name text) -- return a table's integrity level
 */
Datum
mic_get_table_level(PG_FUNCTION_ARGS)
{
	text	   *table_text = PG_GETARG_TEXT_PP(0);
	RangeVar   *rv;
	Oid			rel_oid;
	int			level;

	rv = makeRangeVarFromNameList(textToQualifiedNameList(table_text));
	rel_oid = RangeVarGetRelid(rv, NoLock, false);
	level = mic_get_object_level(RelationRelationId, rel_oid);

	PG_RETURN_TEXT_P(cstring_to_text(mic_level_to_string(level)));
}

/*
 * mic_set_role_level(role_name text, level text) -- superuser only
 */
Datum
mic_set_role_level(PG_FUNCTION_ARGS)
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
				 errmsg("pg_mic: only superuser can set role integrity levels")));

	if (mic_level_from_string(level_str) == MIC_LEVEL_INVALID)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("pg_mic: \"%s\" is not a valid integrity level", level_str),
				 errhint("Valid levels are: low, medium, high.")));

	role_oid = get_role_oid(role_name, false);

	object.classId = AuthIdRelationId;
	object.objectId = role_oid;
	object.objectSubId = 0;

	SetSecurityLabel(&object, MIC_LABEL_TAG, level_str);

	PG_RETURN_VOID();
}

/*
 * mic_promote_table(table_name text, new_level text) -- superuser only
 */
Datum
mic_promote_table(PG_FUNCTION_ARGS)
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
				 errmsg("pg_mic: only superuser can promote table integrity levels")));

	if (mic_level_from_string(level_str) == MIC_LEVEL_INVALID)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("pg_mic: \"%s\" is not a valid integrity level", level_str),
				 errhint("Valid levels are: low, medium, high.")));

	rv = makeRangeVarFromNameList(textToQualifiedNameList(table_text));
	rel_oid = RangeVarGetRelid(rv, NoLock, false);

	object.classId = RelationRelationId;
	object.objectId = rel_oid;
	object.objectSubId = 0;

	SetSecurityLabel(&object, MIC_LABEL_TAG, level_str);

	PG_RETURN_VOID();
}

/*
 * mic_promote_object(class_id oid, object_id oid, new_level text)
 * -- superuser only, generic object promotion
 */
Datum
mic_promote_object(PG_FUNCTION_ARGS)
{
	Oid			class_id = PG_GETARG_OID(0);
	Oid			object_id = PG_GETARG_OID(1);
	text	   *level_text = PG_GETARG_TEXT_PP(2);
	char	   *level_str = text_to_cstring(level_text);
	ObjectAddress object;

	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("pg_mic: only superuser can promote object integrity levels")));

	if (mic_level_from_string(level_str) == MIC_LEVEL_INVALID)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("pg_mic: \"%s\" is not a valid integrity level", level_str),
				 errhint("Valid levels are: low, medium, high.")));

	object.classId = class_id;
	object.objectId = object_id;
	object.objectSubId = 0;

	SetSecurityLabel(&object, MIC_LABEL_TAG, level_str);

	PG_RETURN_VOID();
}

/*
 * mic_initialize_labels() -- label all existing user tables at the
 * caller's integrity level.  Superuser only.
 */
Datum
mic_initialize_labels(PG_FUNCTION_ARGS)
{
	const char *level_str;
	Relation	pg_class;
	TableScanDesc scan;
	HeapTuple	tuple;

	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("pg_mic: only superuser can initialize labels")));

	level_str = mic_level_to_string(mic_get_subject_level());

	pg_class = table_open(RelationRelationId, AccessShareLock);
	scan = table_beginscan_catalog(pg_class, 0, NULL);

	while ((tuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
	{
		Form_pg_class classForm = (Form_pg_class) GETSTRUCT(tuple);
		Oid			relOid = classForm->oid;
		ObjectAddress object;
		char	   *existing;

		/* Skip system objects */
		if (relOid < MIC_SYSTEM_OID_THRESHOLD)
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

		existing = GetSecurityLabel(&object, MIC_LABEL_TAG);
		if (existing != NULL)
		{
			pfree(existing);
			continue;
		}

		SetSecurityLabel(&object, MIC_LABEL_TAG, level_str);
	}

	table_endscan(scan);
	table_close(pg_class, AccessShareLock);

	PG_RETURN_VOID();
}

/*
 * mic_class_supports_seclabel -- conservative list of catalog classes whose
 * objects we label when promoting extension members.
 */
static bool
mic_class_supports_seclabel(Oid classId)
{
	switch (classId)
	{
		case RelationRelationId:
		case ProcedureRelationId:
		case TypeRelationId:
		case NamespaceRelationId:
			return true;
		default:
			return false;
	}
}

/*
 * mic_promote_extension(ext_name text, new_level text) -- superuser only.
 * Relabel every labelable member object of the extension; returns count.
 */
Datum
mic_promote_extension(PG_FUNCTION_ARGS)
{
	char	   *extname = text_to_cstring(PG_GETARG_TEXT_PP(0));
	char	   *level = text_to_cstring(PG_GETARG_TEXT_PP(1));
	Oid			extoid;
	Relation	deprel;
	ScanKeyData skey[2];
	SysScanDesc scan;
	HeapTuple	tup;
	int			count = 0;

	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("pg_mic: only superuser can promote extensions")));
	if (mic_level_from_string(level) == MIC_LEVEL_INVALID)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("pg_mic: \"%s\" is not a valid integrity level", level),
				 errhint("Valid levels are: low, medium, high.")));

	extoid = get_extension_oid(extname, false);

	deprel = table_open(DependRelationId, AccessShareLock);
	ScanKeyInit(&skey[0], Anum_pg_depend_refclassid, BTEqualStrategyNumber,
				F_OIDEQ, ObjectIdGetDatum(ExtensionRelationId));
	ScanKeyInit(&skey[1], Anum_pg_depend_refobjid, BTEqualStrategyNumber,
				F_OIDEQ, ObjectIdGetDatum(extoid));
	scan = systable_beginscan(deprel, DependReferenceIndexId, true, NULL, 2, skey);
	while (HeapTupleIsValid(tup = systable_getnext(scan)))
	{
		Form_pg_depend dep = (Form_pg_depend) GETSTRUCT(tup);
		ObjectAddress obj;

		if (dep->deptype != DEPENDENCY_EXTENSION)
			continue;
		obj.classId = dep->classid;
		obj.objectId = dep->objid;
		obj.objectSubId = dep->objsubid;

		if (!mic_class_supports_seclabel(obj.classId))
		{
			if (mic_debug_audit)
				ereport(LOG,
						(errmsg("pg_mic: skipping unlabelable member class %u obj %u",
								obj.classId, obj.objectId)));
			continue;
		}
		SetSecurityLabel(&obj, MIC_LABEL_TAG, level);
		count++;
	}
	systable_endscan(scan);
	table_close(deprel, AccessShareLock);

	PG_RETURN_INT32(count);
}
