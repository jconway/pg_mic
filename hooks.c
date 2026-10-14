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
#include "catalog/pg_extension.h"
#include "catalog/pg_inherits.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_operator.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_rewrite.h"
#include "catalog/pg_type.h"
#include "commands/seclabel.h"
#include "executor/executor.h"
#include "fmgr.h"
#include "miscadmin.h"
#include "nodes/nodeFuncs.h"
#include "nodes/parsenodes.h"
#include "optimizer/planner.h"
#include "parser/parse_func.h"
#include "parser/parse_type.h"
#include "pg_mic.h"
#include "pg_mic_compat.h"
#include "tcop/utility.h"
#include "utils/guc.h"
#include "utils/lsyscache.h"
#include "utils/queryenvironment.h"

MIC_MODULE_MAGIC;

/*
 * Saved hook entries (for chaining)
 */
static object_access_hook_type next_object_access_hook = NULL;
static ExecutorCheckPerms_hook_type next_exec_check_perms_hook = NULL;
static ProcessUtility_hook_type next_ProcessUtility_hook = NULL;
static needs_fmgr_hook_type next_needs_fmgr_hook = NULL;
static fmgr_hook_type next_fmgr_hook = NULL;
static planner_hook_type next_planner_hook = NULL;

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
 * The catalog classes whose objects carry an integrity label.  Relations,
 * functions, rules and operators are labeled at creation; types, schemas
 * and extensions only by explicit promotion.  Altering or dropping any of
 * them is a write to the object.
 */
static bool
mic_class_is_labeled(Oid classId)
{
	switch (classId)
	{
		case RelationRelationId:
		case ProcedureRelationId:
		case RewriteRelationId:
		case OperatorRelationId:
		case TypeRelationId:
		case NamespaceRelationId:
		case ExtensionRelationId:
			return true;
		default:
			return false;
	}
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
				 * Relations, functions, rules and operators are all code
				 * or data a subject can be made to run or read, so each is
				 * labeled at creation.  Skip internal creations (toast
				 * tables, indexes from ALTER TABLE, etc).
				 *
				 * CREATE OR REPLACE (of a function, a rule, or a view's
				 * rule) fires this hook for the existing object as well.
				 * Replacing an object is writing it, so a subject below the
				 * object's current level is refused; otherwise the object
				 * takes the replacing subject's level, since its new
				 * definition is that subject's code.
				 */
				if (!is_internal && subId == 0 &&
					(classId == RelationRelationId ||
					 classId == ProcedureRelationId ||
					 classId == RewriteRelationId ||
					 classId == OperatorRelationId))
				{
					ObjectAddress object;
					const char *level_str;
					char	   *existing;

					object.classId = classId;
					object.objectId = objectId;
					object.objectSubId = 0;

					existing = GetSecurityLabel(&object, MIC_LABEL_TAG);
					if (existing != NULL)
					{
						pfree(existing);
						mic_check_write(classId, objectId);
					}

					/*
					 * Plain SetSecurityLabel, not mic_set_label: the
					 * creating command has just inserted or updated the
					 * object's own catalog row, which already broadcasts
					 * the invalidation a relabel needs, and updating that
					 * row again in the same command would fail with
					 * "tuple already updated by self".
					 */
					level_str = mic_level_to_string(mic_get_subject_level());
					SetSecurityLabel(&object, MIC_LABEL_TAG, level_str);
				}
				/* a new column (subId = attnum) is a write to its relation */
				else if (!is_internal && subId != 0 &&
						 classId == RelationRelationId)
					mic_check_write(classId, objectId);
			}
			break;

		case OAT_DROP:
			{
				ObjectAccessDrop *drop_arg = (ObjectAccessDrop *) arg;

				if ((drop_arg->dropflags & PERFORM_DELETION_INTERNAL) != 0)
					break;

				/* subId != 0 is a column of the relation: still a write */
				if (mic_class_is_labeled(classId))
					mic_check_write(classId, objectId);
			}
			break;

		case OAT_POST_ALTER:
			{
				ObjectAccessPostAlter *pa_arg = arg;

				if (pa_arg->is_internal)
					break;

				if (mic_class_is_labeled(classId))
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
				 *
				 * This hook fires from the executor's expression setup, so
				 * it denies at plan/initialization time.  The function
				 * manager hook below is the authoritative guard for every
				 * call site, including those that never go through here.
				 */
				mic_check_function_call(objectId);
			}
			break;

		default:
			elog(ERROR, "pg_mic: unexpected object access type: %d",
				 (int) access);
			break;
	}
}

/*
 * Function-manager hooks: the universal runtime backstop.
 *
 * The object-access hook above is only invoked from a handful of executor
 * sites.  Trigger functions (trigger.c), event triggers, the logical
 * replication apply path, type support functions such as a range type's
 * subtype_diff, and anything else PostgreSQL calls through fmgr_info() +
 * FunctionCallInvoke() never pass through it.  They all do pass through the
 * function manager, and once needs_fmgr_hook() says a function is of
 * interest, fmgr routes every one of its invocations through
 * fmgr_security_definer, which calls fmgr_hook at entry.  Checking the
 * current subject against the function's level there closes every call
 * site at once.  Note that fmgr_security_definer has already switched the
 * current user to the function's owner when fmgr_hook runs; the subject is
 * computed from the outer user as well (see mic_get_subject_level), so a
 * SECURITY DEFINER function cannot launder a lower owner past this check.
 *
 * SQL functions that the planner inlines are never invoked through fmgr, so
 * they are not seen here; their bodies are expressions whose own function
 * calls are.  That is precisely the one accepted exception.
 */
static bool
mic_needs_fmgr_hook(Oid fn_oid)
{
	if (next_needs_fmgr_hook && (*next_needs_fmgr_hook) (fn_oid))
		return true;

	/* built-ins are exempt by definition */
	if (fn_oid < MIC_SYSTEM_OID_THRESHOLD)
		return false;

	/*
	 * A function labeled HIGH can be executed by every subject, so it never
	 * needs checking -- and, because the planner refuses to inline a hooked
	 * function, leaving HIGH functions unhooked is what keeps HIGH SQL
	 * functions inlinable.  Everything below HIGH is hooked (and hence not
	 * inlined): it is denied outright to any higher subject.  This decision
	 * is independent of mic.mode so that a mode change can never leave a
	 * stale, unhooked FmgrInfo behind; the hook itself honors the mode.
	 */
	return mic_get_object_level(ProcedureRelationId, fn_oid) < MIC_LEVEL_HIGH;
}

static void
mic_fmgr_hook(FmgrHookEventType event, FmgrInfo *flinfo, Datum *private)
{
	if (event == FHET_START && mic_mode != MIC_MODE_DISABLED)
		mic_check_function_call(flinfo->fn_oid);

	if (next_fmgr_hook)
		(*next_fmgr_hook) (event, flinfo, private);
}

/*
 * Operators are resolved by name through search_path, so a lower subject can
 * define, say, public.=(int, int) over a built-in function with the wrong
 * semantics and have a higher subject's query silently pick it up: no lower
 * function ever executes, so the function checks never fire.  Operators are
 * therefore labeled at creation like functions, and every query is walked
 * here, after rewriting and before planning, for user-defined operators
 * below the subject.  (Sort and grouping operators always come from an
 * operator class, which only a superuser can create, so only direct
 * operator applications need checking.)
 */
typedef struct OpCheckCtx
{
	int			subject_level;
} OpCheckCtx;

static bool
mic_operator_walker(Node *node, OpCheckCtx *ctx)
{
	if (node == NULL)
		return false;
	switch (nodeTag(node))
	{
		case T_OpExpr:
		case T_DistinctExpr:
		case T_NullIfExpr:
			mic_check_one_operator(((OpExpr *) node)->opno, ctx->subject_level,
								   "query", NULL);
			break;
		case T_ScalarArrayOpExpr:
			mic_check_one_operator(((ScalarArrayOpExpr *) node)->opno,
								   ctx->subject_level, "query", NULL);
			break;
		case T_RowCompareExpr:
			{
				ListCell   *lc;

				foreach(lc, ((RowCompareExpr *) node)->opnos)
					mic_check_one_operator(lfirst_oid(lc), ctx->subject_level,
										   "query", NULL);
				break;
			}
		default:
			break;
	}
	if (IsA(node, Query))
		return query_tree_walker((Query *) node, mic_operator_walker, ctx, 0);
	return expression_tree_walker(node, mic_operator_walker, ctx);
}

MIC_PLANNER_PROTO(mic_planner)
{
	if (mic_mode != MIC_MODE_DISABLED)
	{
		OpCheckCtx	ctx;

		ctx.subject_level = mic_get_subject_level();
		if (ctx.subject_level > MIC_LEVEL_LOW)
			(void) mic_operator_walker((Node *) parse, &ctx);
	}

	if (next_planner_hook)
		return MIC_CALL_PLANNER(next_planner_hook);
	return MIC_CALL_PLANNER(standard_planner);
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
 * Best-effort walk of a raw (unanalyzed) expression: resolve each FuncCall
 * by name and check it against the subject.  Anything that cannot be
 * resolved is silently skipped (never an error); the runtime hooks remain
 * the authoritative guard once the command executes.
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

/* Resolve a bare function name (CREATE TRIGGER / CREATE EVENT TRIGGER). */
static void
mic_check_raw_funcname(List *funcname, RawFuncCtx *ctx)
{
#if PG_VERSION_NUM >= 190000
	int			fgc_flags = 0;
#endif
	FuncCandidateList cands = MIC_FUNCNAME_GET_CANDIDATES(funcname);

	if (cands != NULL && cands->next == NULL)
		mic_check_one_function(cands->oid, ctx->subject_level,
							   ctx->what, ctx->objname);
}

/* Walk the expressions and predicate of a raw IndexStmt. */
static void
mic_walk_index_stmt(IndexStmt *is, RawFuncCtx *ctx)
{
	ListCell   *lc;

	foreach(lc, is->indexParams)
	{
		IndexElem  *ie = lfirst_node(IndexElem, lc);

		if (ie->expr)
			(void) mic_raw_func_walker(ie->expr, ctx);
	}
	if (is->whereClause)
		(void) mic_raw_func_walker(is->whereClause, ctx);
}

/* Walk every raw expression a table Constraint can carry. */
static void
mic_walk_constraint(Constraint *c, RawFuncCtx *ctx)
{
	ListCell   *lc;

	(void) mic_raw_func_walker(c->raw_expr, ctx);
	(void) mic_raw_func_walker(c->where_clause, ctx);
	foreach(lc, c->exclusions)
	{
		List	   *pair = (List *) lfirst(lc);
		IndexElem  *ie = linitial_node(IndexElem, pair);

		if (ie->expr)
			(void) mic_raw_func_walker(ie->expr, ctx);
	}
}

/*
 * A definition derived from another relation (LIKE, INHERITS, PARTITION OF,
 * ATTACH PARTITION, INHERIT) reads that relation's definition and adopts its
 * stored code, so it is both a read of that object and a reach into every
 * function its constraints, defaults and indexes name.
 */
static void
mic_check_source_relation(RangeVar *rv)
{
	Oid			relid = RangeVarGetRelid(rv, AccessShareLock, true);

	if (!OidIsValid(relid))
		return;
	mic_check_read(RelationRelationId, relid);
	mic_check_reachable_functions(relid, ACL_INSERT | ACL_UPDATE);
}

/*
 * Check the stored index expressions of every relation in a tree, and, for
 * commands that also ANALYZE, its extended-statistics expressions.
 */
static void
mic_check_tree_index_exprs(Oid relid, bool inh, bool stats)
{
	List	   *rels = mic_relation_tree(relid, inh);
	ListCell   *lc;

	foreach(lc, rels)
	{
		mic_check_reindex_exprs(lfirst_oid(lc), false);
		if (stats)
			mic_check_stats_exprs(lfirst_oid(lc));
	}
	list_free(rels);
}

/*
 * Attaching an index, trigger, rule, policy or statistics object to a
 * relation changes what that relation does: it is a write to the relation,
 * and a subject below the relation's level may not perform it even when DAC
 * (ownership) would allow it.
 */
static void
mic_check_definition_write(RangeVar *rv)
{
	Oid			relid;

	if (rv == NULL)
		return;
	relid = RangeVarGetRelid(rv, AccessShareLock, true);
	if (OidIsValid(relid))
		mic_check_write(RelationRelationId, relid);
}

/* A subject below HIGH may not own or create a subscription (see README). */
static void
mic_require_high(int level, const char *what)
{
	if (level < MIC_LEVEL_HIGH && mic_is_enforcing())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("pg_mic: %s requires a high integrity subject", what),
				 errdetail("Rows applied by logical replication are written on the subscription owner's behalf without the DML integrity checks.")));
}

/*
 * mic_utility_command
 *
 * ProcessUtility_hook callback.  Utility commands that run catalog-stored
 * code over rows, or that will do so later under another identity, are
 * checked here against the invoking subject before they execute.
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
						{
							/* COPY FROM routes into partitions; TO scans children */
							List	   *rels = mic_relation_tree(relid,
																cs->relation->inh);
							ListCell   *lc;

							foreach(lc, rels)
								mic_check_reachable_functions(lfirst_oid(lc),
															  cs->is_from ? ACL_INSERT : ACL_SELECT);
							list_free(rels);
						}
					}
					break;
				}
			case T_CreateStmt:
				{
					/*
					 * Refuse to define a table in terms of a lower function:
					 * column defaults, generated columns, CHECK/EXCLUDE
					 * constraints, the partition key, a column type whose
					 * domain CHECKs reach one, and anything adopted from a
					 * LIKE source, an INHERITS parent, or a PARTITION OF
					 * parent.  Nothing runs here yet; this is the symmetric
					 * definition-time refusal CREATE TRIGGER already has.
					 */
					CreateStmt *cs = (CreateStmt *) parsetree;
					int			lvl = mic_get_subject_level();
					RawFuncCtx	ctx;
					ListCell   *lc;

					if (lvl <= MIC_LEVEL_LOW)
						break;
					ctx.subject_level = lvl;
					ctx.objname = cs->relation->relname;
					ctx.what = "CREATE TABLE";
					foreach(lc, cs->tableElts)
					{
						Node	   *elt = (Node *) lfirst(lc);

						if (IsA(elt, ColumnDef))
						{
							ColumnDef  *cd = (ColumnDef *) elt;
							ListCell   *lc2;
							Oid			typid;

							(void) mic_raw_func_walker(cd->raw_default, &ctx);
							foreach(lc2, cd->constraints)
								mic_walk_constraint(lfirst_node(Constraint, lc2), &ctx);
							typid = cd->typeName ?
								LookupTypeNameOid(NULL, cd->typeName, true) : InvalidOid;
							if (OidIsValid(typid))
								mic_check_column_type(typid, lvl, cs->relation->relname);
						}
						else if (IsA(elt, Constraint))
							mic_walk_constraint((Constraint *) elt, &ctx);
						else if (IsA(elt, TableLikeClause))
							mic_check_source_relation(((TableLikeClause *) elt)->relation);
					}
					if (cs->partspec != NULL)
					{
						foreach(lc, cs->partspec->partParams)
						{
							PartitionElem *pe = lfirst_node(PartitionElem, lc);

							if (pe->expr)
								(void) mic_raw_func_walker(pe->expr, &ctx);
						}
					}
					if (cs->ofTypename != NULL)
					{
						Oid			typid = LookupTypeNameOid(NULL, cs->ofTypename, true);

						if (OidIsValid(typid))
							mic_check_column_type(typid, lvl, cs->relation->relname);
					}
					foreach(lc, cs->inhRelations)
						mic_check_source_relation(lfirst_node(RangeVar, lc));
					break;
				}
			case T_IndexStmt:
				{
					IndexStmt  *is = (IndexStmt *) parsetree;
					int			lvl = mic_get_subject_level();

					mic_check_definition_write(is->relation);
					if (lvl > MIC_LEVEL_LOW && is->relation != NULL)
					{
						RawFuncCtx	ctx;

						ctx.subject_level = lvl;
						ctx.objname = is->relation->relname;
						ctx.what = "index definition on";
						mic_walk_index_stmt(is, &ctx);
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

					/*
					 * Whatever the subcommand, ALTER TABLE rewrites the
					 * relation's definition: a write to the relation.  Not
					 * every subcommand reaches the object-access hook
					 * (ADD CONSTRAINT, for one, reports only the new
					 * constraint), so it is checked here once.
					 */
					mic_check_write(RelationRelationId, relid);

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
							case AT_AddIndex:
							case AT_AddIndexConstraint:
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
											mic_walk_constraint((Constraint *) cmd->def, &ctx);
										else if (IsA(cmd->def, IndexStmt))
											mic_walk_index_stmt((IndexStmt *) cmd->def, &ctx);
										else if (IsA(cmd->def, ColumnDef))
										{
											ColumnDef  *cd = (ColumnDef *) cmd->def;
											ListCell   *lc2;

											(void) mic_raw_func_walker(cd->raw_default, &ctx);
											foreach(lc2, cd->constraints)
												mic_walk_constraint(lfirst_node(Constraint, lc2), &ctx);
										}
										else
										{
											/* bare raw expression (SET DEFAULT / SET EXPRESSION) */
											(void) mic_raw_func_walker(cmd->def, &ctx);
										}
									}
									/* validation/rewrite runs stored code over the tree */
									{
										List	   *rels = mic_relation_tree(relid,
																			at->relation->inh);
										ListCell   *lc3;

										foreach(lc3, rels)
											mic_check_reachable_functions(lfirst_oid(lc3),
																		  ACL_INSERT | ACL_UPDATE);
										list_free(rels);
									}
								}
								break;
							case AT_AttachPartition:
							case AT_AddInherit:
								{
									RangeVar   *other = NULL;

									if (at->objtype != OBJECT_TABLE || cmd->def == NULL)
										break;
									if (IsA(cmd->def, PartitionCmd))
										other = ((PartitionCmd *) cmd->def)->name;
									else if (IsA(cmd->def, RangeVar))
										other = (RangeVar *) cmd->def;
									if (other != NULL && mic_get_subject_level() > MIC_LEVEL_LOW)
										mic_check_source_relation(other);
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
						{
							if (rs->kind == REINDEX_OBJECT_INDEX)
								mic_check_reindex_exprs(relid, true);
							else
								mic_check_tree_index_exprs(relid, rs->relation->inh, false);
						}
					}
					else if (rs->kind == REINDEX_OBJECT_SCHEMA)
					{
						Oid			nspoid = get_namespace_oid(rs->name, true);

						if (OidIsValid(nspoid))
							mic_check_reindex_relations(nspoid, false);
					}
					else if (rs->kind == REINDEX_OBJECT_DATABASE)
						mic_check_reindex_relations(InvalidOid, false);
					/*
					 * REINDEX SYSTEM touches only system catalogs, which are
					 * exempt (OID below the threshold), so nothing to check.
					 */
					break;
				}
			case T_VacuumStmt:
				{
					/*
					 * VACUUM (FULL) and ANALYZE evaluate index and statistics
					 * expressions, and REPACK/CLUSTER below rebuild indexes,
					 * all after switching to the table owner's identity.
					 * Like REINDEX, the invoking subject is the one being
					 * lured, so it is checked before the switch.
					 */
					VacuumStmt *vs = (VacuumStmt *) parsetree;
					ListCell   *lc;

					if (vs->rels == NIL)
					{
						mic_check_reindex_relations(InvalidOid, true);
						break;
					}
					foreach(lc, vs->rels)
					{
						VacuumRelation *vr = lfirst_node(VacuumRelation, lc);
						Oid			relid = vr->oid;

						if (!OidIsValid(relid) && vr->relation != NULL)
							relid = RangeVarGetRelid(vr->relation,
													 AccessShareLock, true);
						if (OidIsValid(relid))
							mic_check_tree_index_exprs(relid,
													   vr->relation ? vr->relation->inh : true,
													   true);
					}
					break;
				}
#if PG_VERSION_NUM >= 190000
			case T_RepackStmt:
				{
					/* REPACK / CLUSTER / VACUUM FULL: relation is a VacuumRelation */
					RepackStmt *cs = (RepackStmt *) parsetree;
					RangeVar   *rv = cs->relation ? cs->relation->relation : NULL;
					Oid			relid = cs->relation ? cs->relation->oid : InvalidOid;
#else
			case T_ClusterStmt:
				{
					ClusterStmt *cs = (ClusterStmt *) parsetree;
					RangeVar   *rv = cs->relation;
					Oid			relid = InvalidOid;
#endif
					if (!OidIsValid(relid) && rv != NULL)
						relid = RangeVarGetRelid(rv, AccessShareLock, true);
					if (OidIsValid(relid))
						mic_check_tree_index_exprs(relid, rv ? rv->inh : true, true);
					else if (rv == NULL)
						mic_check_reindex_relations(InvalidOid, true);
					break;
				}
			case T_RefreshMatViewStmt:
				{
					RefreshMatViewStmt *rm = (RefreshMatViewStmt *) parsetree;
					Oid			relid = RangeVarGetRelid(rm->relation,
														 AccessShareLock,
														 true);

					if (OidIsValid(relid))
						mic_check_matview_refresh(relid);
					break;
				}
			case T_CreateStatsStmt:
				{
					/*
					 * Statistics expressions run at every ANALYZE, including
					 * autovacuum's; refuse to attach a lower-level function
					 * to a table in the first place.
					 */
					CreateStatsStmt *st = (CreateStatsStmt *) parsetree;
					int			lvl = mic_get_subject_level();
					ListCell   *lcr;

					foreach(lcr, st->relations)
					{
						if (IsA(lfirst(lcr), RangeVar))
							mic_check_definition_write((RangeVar *) lfirst(lcr));
					}
					if (lvl > MIC_LEVEL_LOW)
					{
						RawFuncCtx	ctx;
						ListCell   *lc;

						ctx.subject_level = lvl;
						ctx.objname = "statistics object";
						ctx.what = "CREATE STATISTICS expression for";
						foreach(lc, st->exprs)
						{
							Node	   *e = (Node *) lfirst(lc);

							if (IsA(e, StatsElem))
								(void) mic_raw_func_walker(((StatsElem *) e)->expr, &ctx);
							else
								(void) mic_raw_func_walker(e, &ctx);
						}
					}
					break;
				}
			case T_CreatePolicyStmt:
			case T_AlterPolicyStmt:
				{
					/* RLS quals run on every row access, in the executor */
					Node	   *qual;
					Node	   *with_check;
					const char *polname;
					int			lvl = mic_get_subject_level();

					if (nodeTag(parsetree) == T_CreatePolicyStmt)
					{
						CreatePolicyStmt *cp = (CreatePolicyStmt *) parsetree;

						qual = cp->qual;
						with_check = cp->with_check;
						polname = cp->policy_name;
						mic_check_definition_write(cp->table);
					}
					else
					{
						AlterPolicyStmt *ap = (AlterPolicyStmt *) parsetree;

						qual = ap->qual;
						with_check = ap->with_check;
						polname = ap->policy_name;
						mic_check_definition_write(ap->table);
					}
					if (lvl > MIC_LEVEL_LOW)
					{
						RawFuncCtx	ctx;

						ctx.subject_level = lvl;
						ctx.objname = polname;
						ctx.what = "policy";
						(void) mic_raw_func_walker(qual, &ctx);
						(void) mic_raw_func_walker(with_check, &ctx);
					}
					break;
				}
			case T_CreateDomainStmt:
				{
					CreateDomainStmt *cd = (CreateDomainStmt *) parsetree;
					int			lvl = mic_get_subject_level();

					if (lvl > MIC_LEVEL_LOW)
					{
						RawFuncCtx	ctx;
						ListCell   *lc;

						ctx.subject_level = lvl;
						ctx.objname = strVal(llast(cd->domainname));
						ctx.what = "CREATE DOMAIN";
						foreach(lc, cd->constraints)
							mic_walk_constraint(lfirst_node(Constraint, lc), &ctx);
					}
					break;
				}
			case T_AlterDomainStmt:
				{
					AlterDomainStmt *ad = (AlterDomainStmt *) parsetree;
					int			lvl = mic_get_subject_level();

					/*
					 * subtype 'C' = ADD CONSTRAINT (def is the Constraint);
					 * 'T' = SET DEFAULT (def is the raw default expression,
					 * which every INSERT omitting a column of the domain's
					 * type then evaluates).
					 */
					if (ad->def != NULL && lvl > MIC_LEVEL_LOW &&
						(ad->subtype == 'C' || ad->subtype == 'T'))
					{
						RawFuncCtx	ctx;

						ctx.subject_level = lvl;
						ctx.objname = strVal(llast(ad->typeName));
						ctx.what = "ALTER DOMAIN";
						if (IsA(ad->def, Constraint))
							mic_walk_constraint((Constraint *) ad->def, &ctx);
						else
							(void) mic_raw_func_walker(ad->def, &ctx);
					}
					break;
				}
			case T_CreateTrigStmt:
				{
					CreateTrigStmt *ct = (CreateTrigStmt *) parsetree;
					int			lvl = mic_get_subject_level();

					mic_check_definition_write(ct->relation);
					if (lvl > MIC_LEVEL_LOW && ct->relation != NULL)
					{
						RawFuncCtx	ctx;

						ctx.subject_level = lvl;
						ctx.objname = ct->relation->relname;
						ctx.what = "CREATE TRIGGER on";
						mic_check_raw_funcname(ct->funcname, &ctx);
						(void) mic_raw_func_walker(ct->whenClause, &ctx);
					}
					break;
				}
			case T_CreateEventTrigStmt:
				{
					CreateEventTrigStmt *ce = (CreateEventTrigStmt *) parsetree;
					int			lvl = mic_get_subject_level();

					if (lvl > MIC_LEVEL_LOW)
					{
						RawFuncCtx	ctx;

						ctx.subject_level = lvl;
						ctx.objname = ce->trigname;
						ctx.what = "CREATE EVENT TRIGGER";
						mic_check_raw_funcname(ce->funcname, &ctx);
					}
					break;
				}
			case T_RuleStmt:
				{
					/*
					 * A rule's actions are queries that later run with the
					 * privileges of whoever touches the table (DAC on them
					 * is checked as the rule owner).  Attaching one is a
					 * write to the relation; a higher subject defining one
					 * in terms of lower functions is refused up front.  The
					 * rule itself is labeled at creation and checked by the
					 * DML layer whenever its event fires.
					 */
					RuleStmt   *rs = (RuleStmt *) parsetree;
					int			lvl = mic_get_subject_level();

					mic_check_definition_write(rs->relation);
					if (lvl > MIC_LEVEL_LOW)
					{
						RawFuncCtx	ctx;
						ListCell   *lc;

						ctx.subject_level = lvl;
						ctx.objname = rs->rulename;
						ctx.what = "CREATE RULE";

						(void) mic_raw_func_walker(rs->whereClause, &ctx);
						foreach(lc, rs->actions)
						{
							Node	   *a = (Node *) lfirst(lc);

							/* the raw walker knows DML; a NOTIFY carries nothing */
							if (IsA(a, SelectStmt) || IsA(a, InsertStmt) ||
								IsA(a, UpdateStmt) || IsA(a, DeleteStmt)
#if PG_VERSION_NUM >= 150000
								|| IsA(a, MergeStmt)
#endif
								)
								(void) mic_raw_func_walker(a, &ctx);
						}
					}
					break;
				}
			case T_CreateSubscriptionStmt:
				mic_require_high(mic_get_subject_level(), "CREATE SUBSCRIPTION");
				break;
			case T_AlterOwnerStmt:
				{
					AlterOwnerStmt *ao = (AlterOwnerStmt *) parsetree;

					if (ao->objectType == OBJECT_SUBSCRIPTION)
					{
						Oid			newowner = get_rolespec_oid(ao->newowner, true);

						if (OidIsValid(newowner))
							mic_require_high(mic_get_role_level_oid(newowner),
											 "ALTER SUBSCRIPTION ... OWNER TO");
					}
					break;
				}
			case T_TruncateStmt:
				{
					TruncateStmt *ts = (TruncateStmt *) parsetree;
					List	   *relids = NIL;
					ListCell   *lc;

					/*
					 * Build the set of explicitly-named relations whose
					 * TRUNCATE triggers will fire, expanding inheritance and
					 * partition trees (unless ONLY was given, honoring
					 * rv->inh).  reach.c adds the CASCADE FK closure.
					 */
					foreach(lc, ts->relations)
					{
						RangeVar   *rv = lfirst_node(RangeVar, lc);
						Oid			relid = RangeVarGetRelid(rv, AccessShareLock,
															 true);

						if (!OidIsValid(relid))
							continue;
						if (rv->inh)
							relids = list_concat(relids,
												 find_all_inheritors(relid,
																	 AccessShareLock,
																	 NULL));
						else
							relids = lappend_oid(relids, relid);
					}
					if (relids != NIL)
						mic_check_truncate_triggers(relids,
													ts->behavior == DROP_CASCADE);
					list_free(relids);
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

	MIC_MARK_GUC_PREFIX_RESERVED("mic");

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

	/* Function manager hooks: every invocation of every user function */
	next_needs_fmgr_hook = needs_fmgr_hook;
	needs_fmgr_hook = mic_needs_fmgr_hook;
	next_fmgr_hook = fmgr_hook;
	fmgr_hook = mic_fmgr_hook;

	/* Planner hook: user-defined operators in every query */
	next_planner_hook = planner_hook;
	planner_hook = mic_planner;
}
