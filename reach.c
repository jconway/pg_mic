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
#include "access/htup_details.h"
#include "access/tupdesc.h"
#include "catalog/pg_attribute.h"
#include "catalog/pg_aggregate.h"
#include "catalog/pg_class.h"
#include "catalog/pg_constraint.h"
#include "catalog/pg_policy.h"
#include "catalog/indexing.h"
#include "catalog/pg_type.h"
#include "access/skey.h"
#include "utils/fmgroids.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_trigger.h"
#include "commands/trigger.h"
#include "miscadmin.h"
#include "nodes/nodeFuncs.h"
#include "nodes/nodes.h"
#include "pg_mic.h"
#include "pg_mic_compat.h"
#include "rewrite/rowsecurity.h"
#include "utils/acl.h"
#include "utils/array.h"
#include "utils/builtins.h"
#include "utils/lsyscache.h"
#include "utils/rel.h"
#include "utils/relcache.h"
#include "utils/syscache.h"
#include "utils/typcache.h"

typedef struct FuncCollectCtx
{
	List	   *funcids;
} FuncCollectCtx;

static void
collect_oid(FuncCollectCtx *ctx, Oid f)
{
	if (OidIsValid(f))
		ctx->funcids = lappend_oid(ctx->funcids, f);
}

/* Collect an aggregate's own function plus its support functions. */
static void
collect_aggregate(FuncCollectCtx *ctx, Oid aggfnoid)
{
	HeapTuple	tup;

	collect_oid(ctx, aggfnoid);
	tup = SearchSysCache1(AGGFNOID, ObjectIdGetDatum(aggfnoid));
	if (HeapTupleIsValid(tup))
	{
		Form_pg_aggregate agg = (Form_pg_aggregate) GETSTRUCT(tup);

		collect_oid(ctx, agg->aggtransfn);
		collect_oid(ctx, agg->aggfinalfn);
		collect_oid(ctx, agg->aggcombinefn);
		collect_oid(ctx, agg->aggserialfn);
		collect_oid(ctx, agg->aggdeserialfn);
		collect_oid(ctx, agg->aggmtransfn);
		collect_oid(ctx, agg->aggminvtransfn);
		collect_oid(ctx, agg->aggmfinalfn);
		ReleaseSysCache(tup);
	}
}

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
			collect_aggregate(ctx, ((Aggref *) node)->aggfnoid);
			break;
		case T_WindowFunc:
			collect_aggregate(ctx, ((WindowFunc *) node)->winfnoid);
			break;
		case T_RowCompareExpr:
			{
				ListCell   *lc;

				foreach(lc, ((RowCompareExpr *) node)->opnos)
					collect_oid(ctx, get_opcode(lfirst_oid(lc)));
				break;
			}
		case T_MinMaxExpr:
			{
				TypeCacheEntry *tce;

				tce = lookup_type_cache(((MinMaxExpr *) node)->minmaxtype,
										TYPECACHE_CMP_PROC);
				collect_oid(ctx, tce->cmp_proc);
				break;
			}
		case T_SubscriptingRef:
			collect_oid(ctx,
						get_typsubscript(((SubscriptingRef *) node)->refcontainertype,
										 NULL));
			break;
		case T_XmlExpr:
			/* xml functions are all built-in: nothing to collect */
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
	char	   *fname;

	if (!OidIsValid(funcid) || funcid < MIC_SYSTEM_OID_THRESHOLD)
		return;					/* built-in / system: exempt */

	objlevel = mic_get_object_level(ProcedureRelationId, funcid);

	if (objlevel < subject_level)
	{
		fname = get_func_name(funcid);
		if (fname == NULL)
			fname = "(unknown)";
		if (mic_debug_audit)
			ereport(LOG,
					(errmsg("pg_mic: execute denied - subject %s > function %s \"%s\" (func %u) via %s \"%s\"",
							mic_level_to_string(subject_level),
							mic_level_to_string(objlevel), fname, funcid, via, objname)));
		if (mic_is_enforcing())
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("pg_mic: execute denied - %s integrity subject cannot execute %s integrity function \"%s\" reached via %s \"%s\"",
							mic_level_to_string(subject_level),
							mic_level_to_string(objlevel), fname, via, objname)));
		else
			ereport(WARNING,
					(errmsg("pg_mic: execute violation (permissive) of function \"%s\" via %s \"%s\"",
							fname, via, objname)));
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
		{
			ereport(mic_is_enforcing() ? ERROR : WARNING,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("pg_mic: cannot analyze CHECK constraint \"%s\" on \"%s\"",
							constr->check[i].ccname,
							RelationGetRelationName(rel))));
			continue;
		}
		expr = stringToNode(ccbin);
		mic_check_expr_functions(expr, subject_level, "CHECK constraint on",
								 RelationGetRelationName(rel));
	}
}

/* Triggers on rel whose event matches the operation being performed */
static void
check_triggers(Relation rel, int subject_level, AclMode required_ops)
{
	TriggerDesc *td = rel->trigdesc;
	int			i;

	if (td == NULL)
		return;
	for (i = 0; i < td->numtriggers; i++)
	{
		Trigger    *tg = &td->triggers[i];
		int16		t = tg->tgtype;
		bool		want = false;

		if ((required_ops & ACL_INSERT) && TRIGGER_FOR_INSERT(t))
			want = true;
		if ((required_ops & ACL_UPDATE) && TRIGGER_FOR_UPDATE(t))
			want = true;
		if ((required_ops & ACL_DELETE) && TRIGGER_FOR_DELETE(t))
			want = true;
		if (!want)
			continue;
		mic_check_one_function(tg->tgfoid, subject_level,
							   "trigger on", RelationGetRelationName(rel));
	}
}

/*
 * Column defaults and generated columns.  Plain defaults and STORED generated
 * columns are evaluated on write; VIRTUAL generated columns (PG18+) are
 * evaluated on read (and checked conservatively on write too).
 */
static void
check_defaults_and_generated(Relation rel, int subject_level, AclMode required_ops)
{
	TupleDesc	td = RelationGetDescr(rel);
	TupleConstr *constr = td->constr;
	bool		is_write = (required_ops & (ACL_INSERT | ACL_UPDATE)) != 0;
#if PG_VERSION_NUM >= 180000
	bool		is_read = (required_ops & ACL_SELECT) != 0;
#endif
	int			i;

	if (constr == NULL || constr->num_defval == 0)
		return;

	for (i = 0; i < constr->num_defval; i++)
	{
		AttrDefault *d = &constr->defval[i];
		Form_pg_attribute att = TupleDescAttr(td, d->adnum - 1);
		char		gen = att->attgenerated;
		bool		want;
		Node	   *expr;

		if (gen == ATTRIBUTE_GENERATED_STORED)
			want = is_write;
#if PG_VERSION_NUM >= 180000
		else if (gen == ATTRIBUTE_GENERATED_VIRTUAL)
			want = is_read || is_write;
#endif
		else
			want = is_write;		/* plain column DEFAULT */

		if (!want)
			continue;
		if (d->adbin == NULL)		/* fail-closed: expected but missing */
		{
			ereport(mic_is_enforcing() ? ERROR : WARNING,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("pg_mic: cannot analyze default expression of column \"%s\" on \"%s\"",
							NameStr(att->attname),
							RelationGetRelationName(rel))));
			continue;
		}
		expr = stringToNode(d->adbin);
		mic_check_expr_functions(expr, subject_level,
								 (gen ? "generated column on" : "column default on"),
								 RelationGetRelationName(rel));
	}
}

static void
check_index_exprs(Relation rel, int subject_level)
{
	List	   *indexoids = RelationGetIndexList(rel);
	ListCell   *lc;

	foreach(lc, indexoids)
	{
		Oid			indexoid = lfirst_oid(lc);
		Relation	irel = index_open(indexoid, AccessShareLock);
		List	   *exprs = RelationGetIndexExpressions(irel);
		List	   *pred = RelationGetIndexPredicate(irel);
		ListCell   *l2;

		foreach(l2, exprs)
			mic_check_expr_functions((Node *) lfirst(l2), subject_level,
									 "index expression on",
									 RelationGetRelationName(rel));
		foreach(l2, pred)
			mic_check_expr_functions((Node *) lfirst(l2), subject_level,
									 "index predicate on",
									 RelationGetRelationName(rel));
		index_close(irel, AccessShareLock);
	}
	list_free(indexoids);
}

/* Domain CHECK constraints for domain-typed columns (run on write). */
static void
check_domain_of_type(Oid typid, int subject_level, const char *relname)
{
	Relation	conrel;
	ScanKeyData skey;
	SysScanDesc scan;
	HeapTuple	tup;

	if (get_typtype(typid) != TYPTYPE_DOMAIN)
		return;

	conrel = table_open(ConstraintRelationId, AccessShareLock);
	ScanKeyInit(&skey, Anum_pg_constraint_contypid,
				BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(typid));
	scan = systable_beginscan(conrel, ConstraintTypidIndexId, true,
							  NULL, 1, &skey);
	while (HeapTupleIsValid(tup = systable_getnext(scan)))
	{
		Form_pg_constraint c = (Form_pg_constraint) GETSTRUCT(tup);
		Datum		val;
		bool		isnull;

		if (c->contype != CONSTRAINT_CHECK)
			continue;
		val = heap_getattr(tup, Anum_pg_constraint_conbin,
						   RelationGetDescr(conrel), &isnull);
		if (isnull)
		{
			ereport(mic_is_enforcing() ? ERROR : WARNING,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("pg_mic: cannot analyze domain constraint on \"%s\"",
							relname)));
			continue;
		}
		mic_check_expr_functions(stringToNode(TextDatumGetCString(val)),
								 subject_level, "domain CHECK on", relname);
	}
	systable_endscan(scan);
	table_close(conrel, AccessShareLock);
}

static void
check_domain_checks(Relation rel, int subject_level)
{
	TupleDesc	td = RelationGetDescr(rel);
	int			i;

	for (i = 0; i < td->natts; i++)
	{
		Form_pg_attribute att = TupleDescAttr(td, i);

		if (att->attisdropped)
			continue;
		check_domain_of_type(att->atttypid, subject_level,
							 RelationGetRelationName(rel));
	}
}

/* Exclusion-constraint operators: each operator's function runs on write. */
static void
check_exclusion_ops(Relation rel, int subject_level)
{
	Relation	conrel;
	ScanKeyData skey;
	SysScanDesc scan;
	HeapTuple	tup;

	conrel = table_open(ConstraintRelationId, AccessShareLock);
	ScanKeyInit(&skey, Anum_pg_constraint_conrelid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(RelationGetRelid(rel)));
	scan = systable_beginscan(conrel, ConstraintRelidTypidNameIndexId, true,
							  NULL, 1, &skey);
	while (HeapTupleIsValid(tup = systable_getnext(scan)))
	{
		Form_pg_constraint c = (Form_pg_constraint) GETSTRUCT(tup);
		Datum		val;
		bool		isnull;
		ArrayType  *arr;
		Oid		   *ops;
		int			nops;
		int			i;

		if (c->contype != CONSTRAINT_EXCLUSION)
			continue;
		val = heap_getattr(tup, Anum_pg_constraint_conexclop,
						   RelationGetDescr(conrel), &isnull);
		if (isnull)
		{
			ereport(mic_is_enforcing() ? ERROR : WARNING,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("pg_mic: cannot analyze exclusion constraint on \"%s\"",
							RelationGetRelationName(rel))));
			continue;
		}
		arr = DatumGetArrayTypeP(val);	/* conexclop is oid[] */
		nops = ArrayGetNItems(ARR_NDIM(arr), ARR_DIMS(arr));
		ops = (Oid *) ARR_DATA_PTR(arr);
		for (i = 0; i < nops; i++)
		{
			RegProcedure opfn = get_opcode(ops[i]);

			if (OidIsValid(opfn))
				mic_check_one_function(opfn, subject_level,
									   "exclusion operator on",
									   RelationGetRelationName(rel));
		}
	}
	systable_endscan(scan);
	table_close(conrel, AccessShareLock);
}

/*
 * RLS policies: USING quals run on read-ish ops, WITH CHECK quals on write
 * ops.  rd_rsdesc is built lazily (and not at all when the subject bypasses
 * RLS), so if it is absent but the relation has row security, scan pg_policy.
 */
static void
check_rls_policies(Relation rel, int subject_level, AclMode required_ops)
{
	bool		is_read = (required_ops & (ACL_SELECT | ACL_UPDATE | ACL_DELETE)) != 0;
	bool		is_write = (required_ops & (ACL_INSERT | ACL_UPDATE)) != 0;
	const char *relname = RelationGetRelationName(rel);

	if (rel->rd_rsdesc != NULL)
	{
		ListCell   *lc;

		foreach(lc, rel->rd_rsdesc->policies)
		{
			RowSecurityPolicy *p = (RowSecurityPolicy *) lfirst(lc);

			if (is_read && p->qual)
				mic_check_expr_functions((Node *) p->qual, subject_level,
										 "RLS USING policy on", relname);
			if (is_write && p->with_check_qual)
				mic_check_expr_functions((Node *) p->with_check_qual,
										 subject_level,
										 "RLS WITH CHECK policy on", relname);
		}
		return;
	}

	if (!rel->rd_rel->relrowsecurity)
		return;

	{
		Relation	polrel;
		ScanKeyData skey;
		SysScanDesc scan;
		HeapTuple	tup;

		polrel = table_open(PolicyRelationId, AccessShareLock);
		ScanKeyInit(&skey, Anum_pg_policy_polrelid,
					BTEqualStrategyNumber, F_OIDEQ,
					ObjectIdGetDatum(RelationGetRelid(rel)));
		scan = systable_beginscan(polrel, PolicyPolrelidPolnameIndexId, true,
								  NULL, 1, &skey);
		while (HeapTupleIsValid(tup = systable_getnext(scan)))
		{
			Datum		val;
			bool		isnull;

			if (is_read)
			{
				val = heap_getattr(tup, Anum_pg_policy_polqual,
								   RelationGetDescr(polrel), &isnull);
				if (!isnull)
					mic_check_expr_functions(stringToNode(TextDatumGetCString(val)),
											 subject_level,
											 "RLS USING policy on", relname);
			}
			if (is_write)
			{
				val = heap_getattr(tup, Anum_pg_policy_polwithcheck,
								   RelationGetDescr(polrel), &isnull);
				if (!isnull)
					mic_check_expr_functions(stringToNode(TextDatumGetCString(val)),
											 subject_level,
											 "RLS WITH CHECK policy on", relname);
			}
		}
		systable_endscan(scan);
		table_close(polrel, AccessShareLock);
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

	if (relid < MIC_SYSTEM_OID_THRESHOLD)
		return;					/* system relation */

	rel = try_table_open(relid, AccessShareLock);
	if (rel == NULL)
		return;

	if (need_write)
		check_check_constraints(rel, subject_level);
	check_triggers(rel, subject_level, required_ops);
	check_defaults_and_generated(rel, subject_level, required_ops);
	check_index_exprs(rel, subject_level);	/* all ops: planner evaluates too */
	if (need_write)
	{
		check_domain_checks(rel, subject_level);
		check_exclusion_ops(rel, subject_level);
	}
	check_rls_policies(rel, subject_level, required_ops);

	table_close(rel, AccessShareLock);
}
