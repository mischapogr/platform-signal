-- Canonical logical schema inventory; excludes OIDs, storage statistics, role
-- names and configurable ACLs. Caller uses pg_catalog,signal_control,pg_temp.
SELECT encode(sha256(convert_to(jsonb_agg(v ORDER BY v->>'table')::text,'UTF8')),'hex')
FROM (
 SELECT jsonb_build_object('table',c.relname,'kind',c.relkind,'persistence',c.relpersistence,
 'rls',c.relrowsecurity,'forced_rls',c.relforcerowsecurity,
 'columns',(SELECT jsonb_agg(jsonb_build_object('number',a.attnum,'name',a.attname,
     'type',format_type(a.atttypid,a.atttypmod),'notnull',a.attnotnull,'identity',a.attidentity,
     'generated',a.attgenerated,'dropped',a.attisdropped,'default',pg_get_expr(d.adbin,d.adrelid)) ORDER BY a.attnum)
     FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid=c.oid AND a.attnum>0),
 'constraints',(SELECT jsonb_agg(jsonb_build_object('name',k.conname,'type',k.contype,
     'definition',pg_get_constraintdef(k.oid),'deferrable',k.condeferrable,'deferred',k.condeferred,'validated',k.convalidated) ORDER BY k.conname)
     FROM pg_constraint k WHERE k.conrelid=c.oid),
 'indexes',(SELECT jsonb_agg(jsonb_build_object('definition',pg_get_indexdef(i.indexrelid),
     'valid',i.indisvalid,'ready',i.indisready) ORDER BY pg_get_indexdef(i.indexrelid))
     FROM pg_index i WHERE i.indrelid=c.oid)) AS v
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='signal_control' AND c.relkind IN ('r','v','m','f','p')
) inventory;
