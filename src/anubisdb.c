/*
   anubisdb.c

   This file is part of GNU Anubis.
   Copyright (C) 2003 The Anubis Team.

   GNU Anubis is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   GNU Anubis is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with GNU Anubis; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

   GNU Anubis is released under the GPL with the additional exemption that
   compiling, linking, and/or using OpenSSL is allowed.
*/

#include "headers.h"

struct anubis_db_type {
	char *db_id;          
	anubis_db_open_t db_open;
	anubis_db_close_t db_close;
	anubis_db_io_t db_get_record;
	anubis_db_io_t db_put_record;
	anubis_db_strerror_t db_strerror;
};

struct anubis_db_instance {
	struct anubis_db_type *db_type;
	enum anubis_db_mode mode;
	int error_code;
	void *db_handle;
};

static LIST /* of anubis_db_type */ *dbtab;

static int
dbid_cmp(void *item, void *data)
{
	struct anubis_db_type *type = item;
	return strcmp(type->db_id, data);
}

static struct anubis_db_type *
anubis_db_locate(char *name)
{
	return list_locate(dbtab, name, dbid_cmp);
}

int
anubis_db_register(char *dbid,
		   anubis_db_open_t _db_open,
		   anubis_db_close_t _db_close,
		   anubis_db_io_t _db_get,
		   anubis_db_io_t _db_put,
		   anubis_db_strerror_t _db_strerror)
{
	struct anubis_db_type *dbt = xmalloc(sizeof *dbt);
	dbt->db_id = strdup(dbid);
	dbt->db_open = _db_open;
	dbt->db_close = _db_close;
	dbt->db_get_record = _db_get;
	dbt->db_put_record = _db_put;
	dbt->db_strerror = _db_strerror;
	if (!dbtab)
		dbtab = list_create();
	list_append(dbtab, dbt);
	return 0;
}


int
anubis_db_open(char *dbid, char *arg, enum anubis_db_mode mode, void **dptr)
{
	struct anubis_db_instance *inst;
	struct anubis_db_type *dbt = anubis_db_locate(dbid);
	if (!dbt)
		return ENOENT;
	inst = xmalloc(sizeof *inst);
	inst->db_type = dbt;
	inst->db_handle = NULL;
	inst->mode = mode;
	inst->error_code = 0;
	*dptr = inst;
	return dbt->db_open(&inst->db_handle, arg, mode);
}

int
anubis_db_close(void **dptr)
{
	struct anubis_db_instance *inst = *dptr;
	int rc;
	
	if (!inst)
		return EINVAL;
	rc = inst->db_type->db_close(inst->db_handle);
	free(inst);
	*dptr = NULL;
	return rc;
}

int
anubis_db_get_record(void *dptr, char *key, ANUBIS_USER *rec)
{
	struct anubis_db_instance *inst = dptr;
	return inst->db_type->db_get_record(inst->db_handle, key, rec,
					    &inst->error_code);
}

int
anubis_db_put_record(void *dptr, char *key, ANUBIS_USER *rec)
{
	struct anubis_db_instance *inst = dptr;
	if (inst->mode == anubis_db_rdonly) {
		inst->error_code = 0;
		errno = EACCES;
		return 1;
	}
	return inst->db_type->db_put_record(inst->db_handle, key, rec,
					    &inst->error_code);
}

const char *
anubis_db_strerror(void *dptr)
{
	struct anubis_db_instance *inst = dptr;
	if (inst->error_code) {
		int ec = inst->error_code;
		inst->error_code = 0;
		if (inst->db_type->db_strerror) 
			return inst->db_type->db_strerror(inst->db_handle, ec);
	}
	return strerror(errno);
}

void
anubis_db_free_record(ANUBIS_USER *rec)
{
	free(rec->smtp_authid);
	free(rec->smtp_passwd);
	free(rec->username);
	free(rec->rc_file_name);
	memset(rec, 0, sizeof *rec);
}
