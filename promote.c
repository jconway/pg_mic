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
#include "catalog/indexing.h"
#include "catalog/objectaddress.h"
#include "catalog/pg_authid.h"
#include "catalog/pg_class.h"
#include "catalog/pg_depend.h"
#include "catalog/pg_extension.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_operator.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_rewrite.h"
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
#include "utils/syscache.h"
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
	level = mic_get_role_level_oid(role_oid);

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

	mic_set_label(&object, level_str);

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

	mic_set_label(&object, level_str);

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

	mic_set_label(&object, level_str);

	PG_RETURN_VOID();
}

/*
 * The owner of a labelable object, or InvalidOid if the class is unknown or
 * the object has gone.
 */
static Oid
mic_object_owner(Oid classId, Oid objectId)
{
	HeapTuple	tup;
	Oid			owner = InvalidOid;

	switch (classId)
	{
		case RelationRelationId:
			tup = SearchSysCache1(RELOID, ObjectIdGetDatum(objectId));
			if (HeapTupleIsValid(tup))
			{
				owner = ((Form_pg_class) GETSTRUCT(tup))->relowner;
				ReleaseSysCache(tup);
			}
			break;
		case ProcedureRelationId:
			tup = SearchSysCache1(PROCOID, ObjectIdGetDatum(objectId));
			if (HeapTupleIsValid(tup))
			{
				owner = ((Form_pg_proc) GETSTRUCT(tup))->proowner;
				ReleaseSysCache(tup);
			}
			break;
		case TypeRelationId:
			tup = SearchSysCache1(TYPEOID, ObjectIdGetDatum(objectId));
			if (HeapTupleIsValid(tup))
			{
				owner = ((Form_pg_type) GETSTRUCT(tup))->typowner;
				ReleaseSysCache(tup);
			}
			break;
		case NamespaceRelationId:
			tup = SearchSysCache1(NAMESPACEOID, ObjectIdGetDatum(objectId));
			if (HeapTupleIsValid(tup))
			{
				owner = ((Form_pg_namespace) GETSTRUCT(tup))->nspowner;
				ReleaseSysCache(tup);
			}
			break;
		case OperatorRelationId:
			tup = SearchSysCache1(OPEROID, ObjectIdGetDatum(objectId));
			if (HeapTupleIsValid(tup))
			{
				owner = ((Form_pg_operator) GETSTRUCT(tup))->oprowner;
				ReleaseSysCache(tup);
			}
			break;
		default:
			break;
	}
	return owner;
}

/* Label object at level unless it already carries a label; returns 1 if labeled. */
static int
mic_label_if_unlabeled(Oid classId, Oid objectId, int level)
{
	ObjectAddress object;
	char	   *existing;

	object.classId = classId;
	object.objectId = objectId;
	object.objectSubId = 0;

	existing = GetSecurityLabel(&object, MIC_LABEL_TAG);
	if (existing != NULL)
	{
		pfree(existing);
		return 0;
	}
	mic_set_label(&object, mic_level_to_string(level));
	return 1;
}

/*
 * mic_initialize_labels() -- label every unlabeled user table, view,
 * materialized view, rule, function and operator at the level of the role
 * that owns it (the role that wrote it).  Superuser only.
 *
 * Objects that pre-date the extension carry no label and so count as LOW,
 * which is safe but makes a HIGH subject unable to touch them.  Labeling by
 * owner lets a superuser bootstrap a database in one step without
 * promoting a lower role's objects above that role.
 */
Datum
mic_initialize_labels(PG_FUNCTION_ARGS)
{
	Relation	rel;
	TableScanDesc scan;
	HeapTuple	tuple;
	int			count = 0;

	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("pg_mic: only superuser can initialize labels")));

	/* relations, and their rules */
	rel = table_open(RelationRelationId, AccessShareLock);
	scan = table_beginscan_catalog(rel, 0, NULL);
	while ((tuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
	{
		Form_pg_class classForm = (Form_pg_class) GETSTRUCT(tuple);
		Oid			relOid = classForm->oid;
		int			level;

		if (relOid < MIC_SYSTEM_OID_THRESHOLD)
			continue;
		if (classForm->relkind != RELKIND_RELATION &&
			classForm->relkind != RELKIND_PARTITIONED_TABLE &&
			classForm->relkind != RELKIND_VIEW &&
			classForm->relkind != RELKIND_MATVIEW)
			continue;

		level = mic_get_role_level_oid(classForm->relowner);
		count += mic_label_if_unlabeled(RelationRelationId, relOid, level);

		if (classForm->relhasrules)
		{
			Relation	rwrel = table_open(RewriteRelationId, AccessShareLock);
			ScanKeyData skey;
			SysScanDesc rscan;
			HeapTuple	rtup;

			ScanKeyInit(&skey, Anum_pg_rewrite_ev_class,
						BTEqualStrategyNumber, F_OIDEQ,
						ObjectIdGetDatum(relOid));
			rscan = systable_beginscan(rwrel, RewriteRelRulenameIndexId, true,
									   NULL, 1, &skey);
			while (HeapTupleIsValid(rtup = systable_getnext(rscan)))
				count += mic_label_if_unlabeled(RewriteRelationId,
												((Form_pg_rewrite) GETSTRUCT(rtup))->oid,
												level);
			systable_endscan(rscan);
			table_close(rwrel, AccessShareLock);
		}
	}
	table_endscan(scan);
	table_close(rel, AccessShareLock);

	/* functions */
	rel = table_open(ProcedureRelationId, AccessShareLock);
	scan = table_beginscan_catalog(rel, 0, NULL);
	while ((tuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
	{
		Form_pg_proc procForm = (Form_pg_proc) GETSTRUCT(tuple);

		if (procForm->oid < MIC_SYSTEM_OID_THRESHOLD)
			continue;
		count += mic_label_if_unlabeled(ProcedureRelationId, procForm->oid,
										mic_get_role_level_oid(procForm->proowner));
	}
	table_endscan(scan);
	table_close(rel, AccessShareLock);

	/* operators */
	rel = table_open(OperatorRelationId, AccessShareLock);
	scan = table_beginscan_catalog(rel, 0, NULL);
	while ((tuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
	{
		Form_pg_operator oprForm = (Form_pg_operator) GETSTRUCT(tuple);

		if (oprForm->oid < MIC_SYSTEM_OID_THRESHOLD)
			continue;
		count += mic_label_if_unlabeled(OperatorRelationId, oprForm->oid,
										mic_get_role_level_oid(oprForm->oprowner));
	}
	table_endscan(scan);
	table_close(rel, AccessShareLock);

	PG_RETURN_INT32(count);
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
		case OperatorRelationId:
		case TypeRelationId:
		case NamespaceRelationId:
			return true;
		default:
			return false;
	}
}

/*
 * mic_promote_extension(ext_name text, new_level text) -- superuser only.
 * Relabel every labelable member object of the extension, and the extension
 * itself; returns the number of objects relabeled.
 *
 * An extension's members are owned by whoever installed it, and that owner
 * (or anyone who can ALTER EXTENSION ... ADD) can make any object of their
 * own a member.  Promoting a member above its owner's level would therefore
 * promote that owner's code, so members whose owner is below the requested
 * level are skipped, with a warning, and the extension's own label (which
 * ALTER EXTENSION and DROP EXTENSION are then checked against) is set only
 * when nothing was skipped.
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
	int			skipped = 0;
	int			newlevel;

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
	newlevel = mic_level_from_string(level);

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
		if (mic_get_role_level_oid(mic_object_owner(obj.classId, obj.objectId)) < newlevel)
		{
			ereport(WARNING,
					(errmsg("pg_mic: not promoting extension member %s: its owner is below %s",
							getObjectDescription(&obj, false), level)));
			skipped++;
			continue;
		}
		mic_set_label(&obj, level);
		count++;
	}
	systable_endscan(scan);
	table_close(deprel, AccessShareLock);

	if (skipped == 0)
	{
		ObjectAddress ext;

		ext.classId = ExtensionRelationId;
		ext.objectId = extoid;
		ext.objectSubId = 0;
		mic_set_label(&ext, level);
		count++;
	}

	PG_RETURN_INT32(count);
}
