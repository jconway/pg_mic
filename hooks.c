/* -------------------------------------------------------------------------
 *
 * contrib/pg_mic/hooks.c
 *
 * Module initialization and hook dispatch for the Biba integrity model.
 *
 * Copyright (c) 2026, PostgreSQL Global Development Group
 *
 * -------------------------------------------------------------------------
 */
#include "postgres.h"

#include "catalog/dependency.h"
#include "catalog/namespace.h"
#include "catalog/objectaccess.h"
#include "catalog/pg_class.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_proc.h"
#include "commands/seclabel.h"
#include "executor/executor.h"
#include "fmgr.h"
#include "miscadmin.h"
#include "nodes/nodeFuncs.h"
#include "nodes/parsenodes.h"
#include "parser/parse_func.h"
#include "pg_mic.h"
#include "pg_mic_compat.h"
#include "tcop/utility.h"
#include "utils/guc.h"
#include "utils/queryenvironment.h"

MIC_MODULE_MAGIC;

/*
 * Saved hook entries (for chaining)
 */
static object_access_hook_type next_object_access_hook = NULL;
static ExecutorCheckPerms_hook_type next_exec_check_perms_hook = NULL;
static ProcessUtility_hook_type next_ProcessUtility_hook = NULL;

/*
 * GUC variables
 */
int			mic_mode = MIC_MODE_ENFORCING;
bool		mic_debug_audit = false;

static const struct config_enum_entry mic_mode_options[] = {
	{"disabled", MIC_MODE_DISABLED, false},
	{"permissive", MIC_MODE_PERMISSIVE, false},
	{"enforcing", MIC_MODE_ENFORCING, false},
	{NULL, 0, false}
};

bool
mic_is_enforcing(void)
{
	return mic_mode == MIC_MODE_ENFORCING;
}

/*
 * mic_object_access
 *
 * object_access_hook callback: dispatches based on access type.
 */
static void
mic_object_access(ObjectAccessType access,
				   Oid classId,
				   Oid objectId,
				   int subId,
				   void *arg)
{
	if (next_object_access_hook)
		(*next_object_access_hook) (access, classId, objectId, subId, arg);

	/* Skip if disabled */
	if (mic_mode == MIC_MODE_DISABLED)
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

					level_str = mic_level_to_string(mic_get_subject_level());
					SetSecurityLabel(&object, MIC_LABEL_TAG, level_str);
				}
			}
			break;

		case OAT_DROP:
			{
				ObjectAccessDrop *drop_arg = (ObjectAccessDrop *) arg;

				if ((drop_arg->dropflags & PERFORM_DELETION_INTERNAL) != 0)
					break;

				if (classId == RelationRelationId && subId == 0)
					mic_check_write(classId, objectId);
			}
			break;

		case OAT_POST_ALTER:
			{
				ObjectAccessPostAlter *pa_arg = arg;

				if (pa_arg->is_internal)
					break;

				if (classId == RelationRelationId && subId == 0)
					mic_check_write(classId, objectId);
			}
			break;

		case OAT_TRUNCATE:
			{
				if (classId == RelationRelationId)
					mic_check_write(classId, objectId);
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
				 * exempt inside mic_check_read, so ordinary SQL keeps
				 * working.  User-defined functions carry the integrity
				 * level of their creator, assigned at OAT_POST_CREATE; the
				 * extension's own functions are created by a superuser
				 * during CREATE EXTENSION and are therefore HIGH.
				 */
				mic_check_read(classId, objectId);
			}
			break;

		default:
			elog(ERROR, "pg_mic: unexpected object access type: %d",
				 (int) access);
			break;
	}
}

/*
 * mic_exec_check_perms
 *
 * ExecutorCheckPerms_hook callback: DML permission checks.
 */
MIC_CHECKPERMS_PROTO(mic_exec_check_perms)
{
	List	   *entries;

	if (next_exec_check_perms_hook &&
		!MIC_CALL_NEXT_CHECKPERMS(next_exec_check_perms_hook,
								  rangeTabls, rteperminfos, abort))
		return false;

	if (mic_mode == MIC_MODE_DISABLED)
		return true;

	entries = MIC_PERM_ENTRIES(rangeTabls, rteperminfos);
	if (!mic_dml_privileges(entries, abort))
		return false;

	return true;
}

/*
 * Best-effort walk of a raw (unanalyzed) CREATE INDEX expression/predicate:
 * resolve each FuncCall by name and check it against the subject.  Anything
 * that cannot be resolved is silently skipped (never an error); the runtime
 * OAT_FUNCTION_EXECUTE hook remains the authoritative guard during the build.
 */
typedef struct RawFuncCtx
{
	int			subject_level;
	const char *objname;
	const char *what;
} RawFuncCtx;

static bool
mic_raw_func_walker(Node *node, RawFuncCtx *ctx)
{
	if (node == NULL)
		return false;
	if (IsA(node, FuncCall))
	{
		FuncCall   *fc = (FuncCall *) node;
#if PG_VERSION_NUM >= 190000
		int			fgc_flags = 0;
#endif
		FuncCandidateList cands;

		/* never errors on ambiguity; skip unless exactly one candidate */
		cands = MIC_FUNCNAME_GET_CANDIDATES(fc->funcname);
		if (cands != NULL && cands->next == NULL)
			mic_check_one_function(cands->oid, ctx->subject_level,
								   ctx->what, ctx->objname);
	}
	return raw_expression_tree_walker(node, mic_raw_func_walker, ctx);
}

/*
 * mic_utility_command
 *
 * ProcessUtility_hook callback: block LOAD in enforcing mode.
 */
static void
mic_utility_command(PlannedStmt *pstmt,
					 const char *queryString,
					 bool readOnlyTree,
					 ProcessUtilityContext context,
					 ParamListInfo params,
					 QueryEnvironment *queryEnv,
					 DestReceiver *dest,
					 QueryCompletion *qc)
{
	Node	   *parsetree = pstmt->utilityStmt;

	if (mic_mode != MIC_MODE_DISABLED)
	{
		if (nodeTag(parsetree) == T_LoadStmt && mic_is_enforcing())
		{
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("pg_mic: LOAD is not permitted in enforcing mode")));
		}

		switch (nodeTag(parsetree))
		{
			case T_CopyStmt:
				{
					CopyStmt   *cs = (CopyStmt *) parsetree;

					if (cs->relation)	/* COPY table, not COPY (query) */
					{
						Oid			relid = RangeVarGetRelid(cs->relation,
															 AccessShareLock,
															 true);

						if (OidIsValid(relid))
							mic_check_reachable_functions(relid,
														  cs->is_from ? ACL_INSERT : ACL_SELECT);
					}
					break;
				}
			case T_IndexStmt:
				{
					IndexStmt  *is = (IndexStmt *) parsetree;
					int			lvl = mic_get_subject_level();

					if (lvl > MIC_LEVEL_LOW && is->relation != NULL)
					{
						RawFuncCtx	ctx;
						ListCell   *lc;

						ctx.subject_level = lvl;
						ctx.objname = is->relation->relname;
						ctx.what = "index definition on";
						foreach(lc, is->indexParams)
						{
							IndexElem  *ie = lfirst_node(IndexElem, lc);

							if (ie->expr)
								(void) mic_raw_func_walker(ie->expr, &ctx);
						}
						if (is->whereClause)
							(void) mic_raw_func_walker(is->whereClause, &ctx);
					}
					break;
				}
			case T_AlterTableStmt:
				{
					AlterTableStmt *at = (AlterTableStmt *) parsetree;
					Oid			relid = RangeVarGetRelid(at->relation,
														 AccessShareLock,
														 true);
					ListCell   *lc;

					if (!OidIsValid(relid))
						break;

					foreach(lc, at->cmds)
					{
						AlterTableCmd *cmd = lfirst_node(AlterTableCmd, lc);

						switch (cmd->subtype)
						{
							case AT_AddConstraint:
							case AT_ValidateConstraint:
							case AT_AlterColumnType:
							case AT_ColumnDefault:
							case AT_CookedColumnDefault:
							case AT_AddIdentity:
#if PG_VERSION_NUM >= 180000
							case AT_SetExpression:
#endif
								{
									int			lvl = mic_get_subject_level();

									if (cmd->def != NULL && lvl > MIC_LEVEL_LOW)
									{
										RawFuncCtx	ctx;

										ctx.subject_level = lvl;
										ctx.objname = at->relation->relname;
										ctx.what = "ALTER TABLE on";
										if (IsA(cmd->def, Constraint))
											(void) mic_raw_func_walker(((Constraint *) cmd->def)->raw_expr, &ctx);
										else if (IsA(cmd->def, ColumnDef))
										{
											ColumnDef  *cd = (ColumnDef *) cmd->def;
											ListCell   *lc2;

											(void) mic_raw_func_walker(cd->raw_default, &ctx);
											foreach(lc2, cd->constraints)
											{
												Constraint *c = lfirst_node(Constraint, lc2);

												(void) mic_raw_func_walker(c->raw_expr, &ctx);
											}
										}
									}
									mic_check_reachable_functions(relid,
																  ACL_INSERT | ACL_UPDATE);
								}
								break;
							default:
								break;
						}
					}
					break;
				}
			case T_ReindexStmt:
				{
					ReindexStmt *rs = (ReindexStmt *) parsetree;

					if (rs->relation != NULL &&
						(rs->kind == REINDEX_OBJECT_INDEX ||
						 rs->kind == REINDEX_OBJECT_TABLE))
					{
						Oid			relid = RangeVarGetRelid(rs->relation,
															 AccessShareLock,
															 true);

						if (OidIsValid(relid))
							mic_check_reindex_exprs(relid,
													rs->kind == REINDEX_OBJECT_INDEX);
					}
					break;
				}
			case T_TruncateStmt:
				{
					TruncateStmt *ts = (TruncateStmt *) parsetree;
					ListCell   *lc;

					foreach(lc, ts->relations)
					{
						RangeVar   *rv = lfirst_node(RangeVar, lc);
						Oid			relid = RangeVarGetRelid(rv, AccessShareLock,
															 true);

						if (OidIsValid(relid))
							mic_check_truncate_triggers(relid);
					}
					break;
				}
			default:
				break;
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
				 errmsg("pg_mic must be loaded via \"shared_preload_libraries\"")));

	/* GUC: mic.mode */
	DefineCustomEnumVariable("mic.mode",
							 "Biba integrity model enforcement mode",
							 NULL,
							 &mic_mode,
							 MIC_MODE_ENFORCING,
							 mic_mode_options,
							 PGC_SIGHUP,
							 0,
							 NULL,
							 NULL,
							 NULL);

	/* GUC: mic.debug_audit */
	DefineCustomBoolVariable("mic.debug_audit",
							 "Turn on/off debug audit messages for Biba checks",
							 NULL,
							 &mic_debug_audit,
							 false,
							 PGC_USERSET,
							 0,
							 NULL,
							 NULL,
							 NULL);

	MarkGUCPrefixReserved("mic");

	/* Security label provider */
	register_label_provider(MIC_LABEL_TAG,
							mic_object_relabel);

	/* Object access hook */
	next_object_access_hook = object_access_hook;
	object_access_hook = mic_object_access;

	/* DML permission check hook */
	next_exec_check_perms_hook = ExecutorCheckPerms_hook;
	ExecutorCheckPerms_hook = mic_exec_check_perms;

	/* ProcessUtility hook */
	next_ProcessUtility_hook = ProcessUtility_hook;
	ProcessUtility_hook = mic_utility_command;
}
