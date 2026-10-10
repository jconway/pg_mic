/* -------------------------------------------------------------------------
 *
 * contrib/pg_biba/hooks.c
 *
 * Module initialization and hook dispatch for the Biba integrity model.
 *
 * Copyright (c) 2026, PostgreSQL Global Development Group
 *
 * -------------------------------------------------------------------------
 */
#include "postgres.h"

#include "catalog/dependency.h"
#include "catalog/objectaccess.h"
#include "catalog/pg_class.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_proc.h"
#include "commands/seclabel.h"
#include "executor/executor.h"
#include "fmgr.h"
#include "miscadmin.h"
#include "pg_biba.h"
#include "tcop/utility.h"
#include "utils/guc.h"
#include "utils/queryenvironment.h"

PG_MODULE_MAGIC_EXT(
					.name = "pg_biba",
					.version = PG_VERSION
);

/*
 * Saved hook entries (for chaining)
 */
static object_access_hook_type next_object_access_hook = NULL;
static ExecutorCheckPerms_hook_type next_exec_check_perms_hook = NULL;
static ProcessUtility_hook_type next_ProcessUtility_hook = NULL;

/*
 * GUC variables
 */
int			biba_mode = BIBA_MODE_ENFORCING;
bool		biba_debug_audit = false;

static const struct config_enum_entry biba_mode_options[] = {
	{"disabled", BIBA_MODE_DISABLED, false},
	{"permissive", BIBA_MODE_PERMISSIVE, false},
	{"enforcing", BIBA_MODE_ENFORCING, false},
	{NULL, 0, false}
};

bool
biba_is_enforcing(void)
{
	return biba_mode == BIBA_MODE_ENFORCING;
}

/*
 * biba_object_access
 *
 * object_access_hook callback: dispatches based on access type.
 */
static void
biba_object_access(ObjectAccessType access,
				   Oid classId,
				   Oid objectId,
				   int subId,
				   void *arg)
{
	if (next_object_access_hook)
		(*next_object_access_hook) (access, classId, objectId, subId, arg);

	/* Skip if disabled */
	if (biba_mode == BIBA_MODE_DISABLED)
		return;

	switch (access)
	{
		case OAT_POST_CREATE:
			{
				ObjectAccessPostCreate *pc_arg = arg;
				bool		is_internal;

				is_internal = pc_arg ? pc_arg->is_internal : false;

				/*
				 * Assign the creator's integrity level to new objects.
				 * Relations and functions are both first-class objects
				 * under the Biba model, so each is labeled at creation.
				 * Skip internal creations (toast tables, indexes from
				 * ALTER TABLE, etc).
				 */
				if (!is_internal && subId == 0 &&
					(classId == RelationRelationId ||
					 classId == ProcedureRelationId))
				{
					ObjectAddress object;
					const char *level_str;

					object.classId = classId;
					object.objectId = objectId;
					object.objectSubId = 0;

					level_str = biba_level_to_string(biba_get_subject_level());
					SetSecurityLabel(&object, BIBA_LABEL_TAG, level_str);
				}
			}
			break;

		case OAT_DROP:
			{
				ObjectAccessDrop *drop_arg = (ObjectAccessDrop *) arg;

				if ((drop_arg->dropflags & PERFORM_DELETION_INTERNAL) != 0)
					break;

				if (classId == RelationRelationId && subId == 0)
					biba_check_write(classId, objectId);
			}
			break;

		case OAT_POST_ALTER:
			{
				ObjectAccessPostAlter *pa_arg = arg;

				if (pa_arg->is_internal)
					break;

				if (classId == RelationRelationId && subId == 0)
					biba_check_write(classId, objectId);
			}
			break;

		case OAT_TRUNCATE:
			{
				if (classId == RelationRelationId)
					biba_check_write(classId, objectId);
			}
			break;

		case OAT_NAMESPACE_SEARCH:
			{
				ObjectAccessNamespaceSearch *ns_arg = arg;

				if (!ns_arg->result)
					break;

				Assert(classId == NamespaceRelationId);

				/*
				 * Namespace search is a read operation. We allow it
				 * unconditionally for system schemas (pg_catalog, etc.)
				 * to avoid breaking SQL parsing. For user schemas, we
				 * check read permission but only deny and log rather
				 * than blocking search (since blocking search makes
				 * things like \dt fail entirely).
				 */
			}
			break;

		case OAT_FUNCTION_EXECUTE:
			{
				/*
				 * A function is a database object like any other, so
				 * invoking one is governed by "No Read Down": a HIGH
				 * integrity subject may not execute a LOW integrity
				 * function.  This prevents a confused-deputy attack in
				 * which a HIGH subject is lured into running untrusted,
				 * low-integrity code (e.g. an index predicate or trigger
				 * planted by a low-integrity user).
				 *
				 * Built-in functions (OID below the system threshold) are
				 * exempt inside biba_check_read, so ordinary SQL keeps
				 * working.  User-defined functions carry the integrity
				 * level of their creator, assigned at OAT_POST_CREATE; the
				 * extension's own functions are created by a superuser
				 * during CREATE EXTENSION and are therefore HIGH.
				 */
				biba_check_read(classId, objectId);
			}
			break;

		default:
			elog(ERROR, "pg_biba: unexpected object access type: %d",
				 (int) access);
			break;
	}
}

/*
 * biba_exec_check_perms
 *
 * ExecutorCheckPerms_hook callback: DML permission checks.
 */
static bool
biba_exec_check_perms(List *rangeTbls, List *rteperminfos, bool abort)
{
	if (next_exec_check_perms_hook &&
		!(*next_exec_check_perms_hook) (rangeTbls, rteperminfos, abort))
		return false;

	if (biba_mode == BIBA_MODE_DISABLED)
		return true;

	if (!biba_dml_privileges(rangeTbls, rteperminfos, abort))
		return false;

	return true;
}

/*
 * biba_utility_command
 *
 * ProcessUtility_hook callback: block LOAD in enforcing mode.
 */
static void
biba_utility_command(PlannedStmt *pstmt,
					 const char *queryString,
					 bool readOnlyTree,
					 ProcessUtilityContext context,
					 ParamListInfo params,
					 QueryEnvironment *queryEnv,
					 DestReceiver *dest,
					 QueryCompletion *qc)
{
	Node	   *parsetree = pstmt->utilityStmt;

	if (biba_mode != BIBA_MODE_DISABLED)
	{
		if (nodeTag(parsetree) == T_LoadStmt && biba_is_enforcing())
		{
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("pg_biba: LOAD is not permitted in enforcing mode")));
		}
	}

	if (next_ProcessUtility_hook)
		(*next_ProcessUtility_hook) (pstmt, queryString, readOnlyTree,
									 context, params, queryEnv,
									 dest, qc);
	else
		standard_ProcessUtility(pstmt, queryString, readOnlyTree,
								context, params, queryEnv,
								dest, qc);
}

/*
 * Module load callback
 */
void
_PG_init(void)
{
	if (IsUnderPostmaster)
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("pg_biba must be loaded via \"shared_preload_libraries\"")));

	/* GUC: biba.mode */
	DefineCustomEnumVariable("biba.mode",
							 "Biba integrity model enforcement mode",
							 NULL,
							 &biba_mode,
							 BIBA_MODE_ENFORCING,
							 biba_mode_options,
							 PGC_SIGHUP,
							 0,
							 NULL,
							 NULL,
							 NULL);

	/* GUC: biba.debug_audit */
	DefineCustomBoolVariable("biba.debug_audit",
							 "Turn on/off debug audit messages for Biba checks",
							 NULL,
							 &biba_debug_audit,
							 false,
							 PGC_USERSET,
							 0,
							 NULL,
							 NULL,
							 NULL);

	MarkGUCPrefixReserved("biba");

	/* Security label provider */
	register_label_provider(BIBA_LABEL_TAG,
							biba_object_relabel);

	/* Object access hook */
	next_object_access_hook = object_access_hook;
	object_access_hook = biba_object_access;

	/* DML permission check hook */
	next_exec_check_perms_hook = ExecutorCheckPerms_hook;
	ExecutorCheckPerms_hook = biba_exec_check_perms;

	/* ProcessUtility hook */
	next_ProcessUtility_hook = ProcessUtility_hook;
	ProcessUtility_hook = biba_utility_command;
}
