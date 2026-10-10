# Copyright (c) 2026, PostgreSQL Global Development Group

pg_mic_sources = files(
  'dml.c',
  'enforce.c',
  'hooks.c',
  'label.c',
  'promote.c',
)

if host_system == 'windows'
  pg_mic_sources += rc_lib_gen.process(win32ver_rc, extra_args: [
    '--NAME', 'pg_mic',
    '--FILEDESC', 'pg_mic - Biba mandatory integrity model',])
endif

pg_mic = shared_module('pg_mic',
  pg_mic_sources,
  c_pch: pch_postgres_h,
  kwargs: contrib_mod_args,
)
contrib_targets += pg_mic

install_data(
  'pg_mic.control',
  'pg_mic--1.0.sql',
  kwargs: contrib_data_args,
)

tests += {
  'name': 'pg_mic',
  'sd': meson.current_source_dir(),
  'bd': meson.current_build_dir(),
  'regress': {
    'sql': [
      'pg_mic',
    ],
  },
}
