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

#include "catalog/catalog.h"
#include "catalog/pg_class.h"
#include "executor/executor.h"
#include "nodes/nodes.h"
#include "pg_mic.h"
#include "pg_mic_compat.h"
#include "utils/lsyscache.h"

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
		out = lappend(out, e);
	}
#endif
	return out;
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
		 * to decide whether to ERROR or just return false.  However, our
		 * check functions always ereport, so we wrap them in PG_TRY if
		 * we need soft failure.
		 */
		if (!abort_on_violation)
		{
			PG_TRY();
			{
				if (need_read && need_write)
					mic_check_readwrite(RelationRelationId, relOid);
				else if (need_read)
					mic_check_read(RelationRelationId, relOid);
				else
					mic_check_write(RelationRelationId, relOid);
			}
			PG_CATCH();
			{
				FlushErrorState();
				return false;
			}
			PG_END_TRY();
		}
		else
		{
			if (need_read && need_write)
				mic_check_readwrite(RelationRelationId, relOid);
			else if (need_read)
				mic_check_read(RelationRelationId, relOid);
			else
				mic_check_write(RelationRelationId, relOid);
		}
	}

	return true;
}
