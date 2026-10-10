# Copyright (c) 2026, PostgreSQL Global Development Group

pg_biba_sources = files(
  'dml.c',
  'enforce.c',
  'hooks.c',
  'label.c',
  'promote.c',
)

if host_system == 'windows'
  pg_biba_sources += rc_lib_gen.process(win32ver_rc, extra_args: [
    '--NAME', 'pg_biba',
    '--FILEDESC', 'pg_biba - Biba mandatory integrity model',])
endif

pg_biba = shared_module('pg_biba',
  pg_biba_sources,
  c_pch: pch_postgres_h,
  kwargs: contrib_mod_args,
)
contrib_targets += pg_biba

install_data(
  'pg_biba.control',
  'pg_biba--1.0.sql',
  kwargs: contrib_data_args,
)

tests += {
  'name': 'pg_biba',
  'sd': meson.current_source_dir(),
  'bd': meson.current_build_dir(),
  'regress': {
    'sql': [
      'pg_biba',
    ],
  },
}
