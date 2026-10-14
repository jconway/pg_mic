/* -------------------------------------------------------------------------
 *
 * contrib/pg_mic/dml.c
 *
 * DML permission checks for the Biba integrity model.
 *
 * SELECT  => read check  (No Read Down)
 * INSERT  => write check (No Write Up)
 * DELETE  => write check (No Write Up)
 * UPDATE  => both read and write check
 *
 * Copyright (c) 2026, PostgreSQL Global Development Group
 *
 * -------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/xact.h"
#include "catalog/catalog.h"
#include "catalog/pg_class.h"
#include "executor/executor.h"
#include "nodes/nodes.h"
#include "pg_mic.h"
#include "pg_mic_compat.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/resowner.h"

/*
 * mic_perm_entries
 *
 * Version-independent view of the relations and permissions a query needs.
 * PG16+ reads RTEPermissionInfo; earlier versions read RangeTblEntry.
 */
List *
mic_perm_entries(List *rangeTabls, List *rteperminfos)
{
	List	   *out = NIL;
	ListCell   *lc;

#if PG_VERSION_NUM >= 160000
	(void) rangeTabls;
	foreach(lc, rteperminfos)
	{
		RTEPermissionInfo *pi = lfirst_node(RTEPermissionInfo, lc);
		MicPermEntry *e = palloc(sizeof(MicPermEntry));

		e->relid = pi->relid;
		e->requiredPerms = pi->requiredPerms;
		e->inh = pi->inh;
		out = lappend(out, e);
	}
#else
	(void) rteperminfos;
	foreach(lc, rangeTabls)
	{
		RangeTblEntry *rte = lfirst_node(RangeTblEntry, lc);
		MicPermEntry *e;

		if (rte->rtekind != RTE_RELATION)
			continue;
		e = palloc(sizeof(MicPermEntry));
		e->relid = rte->relid;
		e->requiredPerms = rte->requiredPerms;
		e->inh = rte->inh;
		out = lappend(out, e);
	}
#endif
	return out;
}

/*
 * Apply the object-level Biba rules and the reachable-function check to one
 * relation.  Callers have already decided need_read / need_write.
 */
static void
mic_check_one_relation(Oid relOid, AclMode requiredPerms,
					   bool need_read, bool need_write)
{
	if (IsCatalogRelationOid(relOid) || relOid < MIC_SYSTEM_OID_THRESHOLD)
		return;

	if (need_read && need_write)
		mic_check_readwrite(RelationRelationId, relOid);
	else if (need_read)
		mic_check_read(RelationRelationId, relOid);
	else
		mic_check_write(RelationRelationId, relOid);
	mic_check_reachable_functions(relOid, requiredPerms);
}

/*
 * Check a relation and, when the statement reaches them, every relation in
 * its inheritance/partition tree.  Permission checks are performed on the
 * parent only (PG16+ records no RTEPermissionInfo for children at all), but
 * triggers, constraints, defaults and index expressions attached to the
 * children run just the same -- INSERT routes rows into partitions, and
 * UPDATE/DELETE/SELECT scan every child -- so the children must be analyzed
 * too.  Rules, by contrast, fire only on the relation named.
 */
static void
mic_check_relation_tree(MicPermEntry *perminfo, bool need_read, bool need_write)
{
	List	   *rels;
	ListCell   *lc;

	/* system relations have no user-defined descendants: nothing to expand */
	if (IsCatalogRelationOid(perminfo->relid) ||
		perminfo->relid < MIC_SYSTEM_OID_THRESHOLD)
		return;

	/*
	 * A LOW subject reading: nothing is below LOW, so neither the read
	 * check nor any reachable-code check can fail.  Skip the tree walk and
	 * the locks it takes on every child.
	 */
	if (!need_write && mic_get_subject_level() <= MIC_LEVEL_LOW)
		return;

	mic_check_rules(perminfo->relid, perminfo->requiredPerms);

	rels = mic_relation_tree(perminfo->relid, perminfo->inh);
	foreach(lc, rels)
		mic_check_one_relation(lfirst_oid(lc), perminfo->requiredPerms,
							   need_read, need_write);
	list_free(rels);
}

/*
 * Run the checks for one entry without letting a denial escape as an error:
 * the executor asks for this (abort = false) when it only wants to know
 * whether a fast path is permitted, e.g. RI_Initial_Check.  The checks open
 * relations and catalog scans, so they must run in a subtransaction that a
 * denial rolls back; FlushErrorState alone would leak those resources.
 */
static bool
mic_check_relation_tree_soft(MicPermEntry *perminfo, bool need_read,
							 bool need_write)
{
	MemoryContext oldcxt = CurrentMemoryContext;
	ResourceOwner oldowner = CurrentResourceOwner;
	bool		ok = true;

	BeginInternalSubTransaction(NULL);
	PG_TRY();
	{
		mic_check_relation_tree(perminfo, need_read, need_write);
		ReleaseCurrentSubTransaction();
	}
	PG_CATCH();
	{
		MemoryContextSwitchTo(oldcxt);
		CurrentResourceOwner = oldowner;
		FlushErrorState();
		RollbackAndReleaseCurrentSubTransaction();
		ok = false;
	}
	PG_END_TRY();
	MemoryContextSwitchTo(oldcxt);
	CurrentResourceOwner = oldowner;

	return ok;
}

/*
 * mic_dml_privileges
 *
 * Entrypoint for DML permission checks.  Iterates over MicPermEntry
 * items and applies Biba checks based on the required permissions.
 */
bool
mic_dml_privileges(List *perm_entries, bool abort_on_violation)
{
	ListCell   *lr;

	foreach(lr, perm_entries)
	{
		MicPermEntry *perminfo = (MicPermEntry *) lfirst(lr);
		Oid			relOid = perminfo->relid;
		bool		need_read = false;
		bool		need_write = false;

		/*
		 * Skip system catalog relations -- these are exempt from Biba
		 * enforcement to allow basic SQL operations to work.
		 */
		if (IsCatalogRelationOid(relOid))
			continue;

		/* Skip system-OID objects */
		if (relOid < MIC_SYSTEM_OID_THRESHOLD)
			continue;

		/* Determine required access types */
		if (perminfo->requiredPerms & ACL_SELECT)
			need_read = true;
		if (perminfo->requiredPerms & ACL_INSERT)
			need_write = true;
		if (perminfo->requiredPerms & ACL_DELETE)
			need_write = true;
		if (perminfo->requiredPerms & ACL_UPDATE)
		{
			need_read = true;
			need_write = true;
		}

		/* Skip if nothing to check */
		if (!need_read && !need_write)
			continue;

		/*
		 * Apply Biba checks.  We use abort_on_violation from the caller
		 * to decide whether to ERROR or just return false.
		 */
		if (!abort_on_violation)
		{
			if (!mic_check_relation_tree_soft(perminfo, need_read, need_write))
				return false;
		}
		else
			mic_check_relation_tree(perminfo, need_read, need_write);
	}

	return true;
}
