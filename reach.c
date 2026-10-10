/* -------------------------------------------------------------------------
 *
 * contrib/pg_mic/reach.c
 *
 * Static reachable-function integrity check.  Reads the stored expression
 * trees attached to a relation and denies execution of any reachable
 * function whose integrity level is below the subject's level.  Because the
 * stored node trees are examined, the check is immune to SQL function
 * inlining at plan time.
 *
 * Copyright (c) 2026, PostgreSQL Global Development Group
 *
 * -------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/genam.h"
#include "access/table.h"
#include "access/transam.h"
#include "catalog/pg_class.h"
#include "catalog/pg_proc.h"
#include "miscadmin.h"
#include "nodes/nodeFuncs.h"
#include "nodes/nodes.h"
#include "pg_mic.h"
#include "pg_mic_compat.h"
#include "utils/acl.h"
#include "utils/lsyscache.h"
#include "utils/rel.h"
#include "utils/relcache.h"

typedef struct FuncCollectCtx
{
	List	   *funcids;
} FuncCollectCtx;

static bool
func_collect_walker(Node *node, FuncCollectCtx *ctx)
{
	if (node == NULL)
		return false;

	switch (nodeTag(node))
	{
		case T_FuncExpr:
			ctx->funcids = lappend_oid(ctx->funcids,
									   ((FuncExpr *) node)->funcid);
			break;
		case T_OpExpr:
		case T_DistinctExpr:
		case T_NullIfExpr:
			{
				OpExpr	   *op = (OpExpr *) node;
				Oid			f = op->opfuncid ? op->opfuncid : get_opcode(op->opno);

				ctx->funcids = lappend_oid(ctx->funcids, f);
				break;
			}
		case T_ScalarArrayOpExpr:
			{
				ScalarArrayOpExpr *sa = (ScalarArrayOpExpr *) node;
				Oid			f = sa->opfuncid ? sa->opfuncid : get_opcode(sa->opno);

				ctx->funcids = lappend_oid(ctx->funcids, f);
				break;
			}
		case T_Aggref:
			ctx->funcids = lappend_oid(ctx->funcids,
									   ((Aggref *) node)->aggfnoid);
			break;
		case T_WindowFunc:
			ctx->funcids = lappend_oid(ctx->funcids,
									   ((WindowFunc *) node)->winfnoid);
			break;
		case T_CoerceViaIO:
			{
				CoerceViaIO *c = (CoerceViaIO *) node;
				Oid			infn;
				Oid			outfn;
				Oid			ioparam;
				bool		isvarlena;

				getTypeInputInfo(c->resulttype, &infn, &ioparam);
				getTypeOutputInfo(exprType((Node *) c->arg), &outfn, &isvarlena);
				ctx->funcids = lappend_oid(ctx->funcids, infn);
				ctx->funcids = lappend_oid(ctx->funcids, outfn);
				break;
			}
		default:
			break;
	}

	if (IsA(node, Query))
		return query_tree_walker((Query *) node, func_collect_walker, ctx, 0);
	return expression_tree_walker(node, func_collect_walker, ctx);
}

void
mic_check_one_function(Oid funcid, int subject_level,
					   const char *via, const char *objname)
{
	int			objlevel;

	if (!OidIsValid(funcid) || funcid < FirstNormalObjectId)
		return;					/* built-in / system: exempt */

	objlevel = mic_get_object_level(ProcedureRelationId, funcid);

	if (objlevel < subject_level)
	{
		if (mic_debug_audit)
			ereport(LOG,
					(errmsg("pg_mic: execute denied - subject %s > function %s (func %u) via %s \"%s\"",
							mic_level_to_string(subject_level),
							mic_level_to_string(objlevel), funcid, via, objname)));
		if (mic_is_enforcing())
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("pg_mic: execute denied - %s integrity subject cannot execute %s integrity function reached via %s \"%s\"",
							mic_level_to_string(subject_level),
							mic_level_to_string(objlevel), via, objname)));
		else
			ereport(WARNING,
					(errmsg("pg_mic: execute violation (permissive) via %s \"%s\"",
							via, objname)));
	}
}

void
mic_check_expr_functions(Node *expr, int subject_level,
						 const char *via, const char *objname)
{
	FuncCollectCtx ctx = {NIL};
	ListCell   *lc;

	if (expr == NULL)
		return;
	(void) func_collect_walker(expr, &ctx);
	foreach(lc, ctx.funcids)
		mic_check_one_function(lfirst_oid(lc), subject_level, via, objname);
}

/* CHECK constraints (relcache rd_att->constr->check[].ccbin). */
static void
check_check_constraints(Relation rel, int subject_level)
{
	TupleConstr *constr = RelationGetDescr(rel)->constr;
	int			i;

	if (constr == NULL || constr->num_check == 0)
		return;

	for (i = 0; i < constr->num_check; i++)
	{
		char	   *ccbin = constr->check[i].ccbin;
		Node	   *expr;

		if (ccbin == NULL)		/* fail-closed: expected but missing */
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("pg_mic: cannot analyze CHECK constraint \"%s\" on \"%s\"",
							constr->check[i].ccname,
							RelationGetRelationName(rel))));
		expr = stringToNode(ccbin);
		mic_check_expr_functions(expr, subject_level, "CHECK constraint on",
								 RelationGetRelationName(rel));
	}
}

void
mic_check_reachable_functions(Oid relid, AclMode required_ops)
{
	int			subject_level;
	Relation	rel;
	bool		need_write = (required_ops & (ACL_INSERT | ACL_UPDATE)) != 0;

	if (mic_mode == MIC_MODE_DISABLED)
		return;

	subject_level = mic_get_subject_level();
	if (subject_level <= MIC_LEVEL_LOW)
		return;					/* fast path: nothing is below LOW */

	if (relid < FirstNormalObjectId)
		return;					/* system relation */

	rel = try_table_open(relid, AccessShareLock);
	if (rel == NULL)
		return;

	if (need_write)
		check_check_constraints(rel, subject_level);
	/* subsequent tasks add: triggers, defaults, generated, index, excl, RLS, domain */

	table_close(rel, AccessShareLock);
}
