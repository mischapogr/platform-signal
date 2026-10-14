-- Explicit stopped additive installation by the existing schema owner.
-- Does not alter frozen publication routines or their identity.
BEGIN;
SET LOCAL lock_timeout='1s';
SET LOCAL statement_timeout='5s';
LOCK TABLE signal_control.store IN ACCESS EXCLUSIVE MODE NOWAIT;
DO $$
BEGIN
 IF (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='signal_control')
  IS DISTINCT FROM current_user OR EXISTS(SELECT 1 FROM signal_control.store WHERE ready) THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED';
 END IF;
END $$;
CREATE SCHEMA signal_state_read;
REVOKE ALL ON SCHEMA signal_state_read FROM PUBLIC;
CREATE FUNCTION signal_state_read.read_state(t jsonb,key_name text,expected_head uuid,expected_schema bytea,expected_routines bytea)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,signal_control,pg_temp AS $$
DECLARE p signal_control.partitions; s signal_control.state; result jsonb;
BEGIN
 IF key_name IS NULL OR octet_length(key_name) NOT BETWEEN 1 AND 256
  OR key_name ~ '[[:cntrl:]]' OR expected_head='00000000-0000-0000-0000-000000000000'::uuid THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID';
 END IF;
 p:=signal_control.check_token(t,expected_schema,expected_routines);
 IF p.kind<>'pipeline' THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FENCED'; END IF;
 IF p.head IS DISTINCT FROM expected_head THEN
  RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CONFLICT';
 END IF;
 SELECT * INTO s FROM signal_control.state WHERE partition_id=p.id AND key=key_name;
 result:=jsonb_build_object('schema_version',1,'partition_id',p.id,'head',p.head,'checkpoint',p.checkpoint,
  'state',CASE WHEN FOUND THEN jsonb_build_object('key',s.key,'revision',encode(s.revision,'hex'),'bytes',encode(s.value,'hex')) ELSE NULL END);
 PERFORM signal_control.check_token(t,expected_schema,expected_routines);
 RETURN result;
END $$;
REVOKE ALL ON FUNCTION signal_state_read.read_state(jsonb,text,uuid,bytea,bytea) FROM PUBLIC;
COMMIT;
