#!/usr/bin/env python3
"""Real offline PostgreSQL install/upgrade and authority qualification."""
import argparse,hashlib,json,os,re,shutil,subprocess,tempfile,time,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
IMAGE='postgres@sha256:fe03a7605299a34ddf5e4f285dff78c3d7190a576b3c6b46f2fcff69f4bffd54'
ROLES=['app_tenant','app_control_plane','app_billing_worker','app_webhook_worker','app_job_worker']

def run(args,check=True,**kw):
    r=subprocess.run(args,text=True,capture_output=True,timeout=120,**kw)
    if check and r.returncode: raise RuntimeError(r.stderr[-600:]+'\n'+r.stdout[-1000:])
    return r

def sql(c,body,user='postgres',check=True):
    return run(['docker','exec','-i',c,'psql','-XqAt','-v','ON_ERROR_STOP=1','-v','VERBOSITY=verbose','-U',user,'-d','users'],input=body,check=check)

def start():
    c='managed-rls-'+uuid.uuid4().hex[:10]
    run(['docker','run','-d','--name',c,'--network','none','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_DB=users',IMAGE])
    for _ in range(160):
        if 'PostgreSQL init process complete' in run(['docker','logs',c]).stdout:
            if sql(c,'SELECT 1',check=False).returncode==0: return c
        time.sleep(.25)
    raise RuntimeError('local PostgreSQL startup failed')

def migrate(c,user,stage,migrate_binary):
    run(['docker','cp',str(stage),c+':/tmp/stage'])
    run(['docker','cp',str(migrate_binary),c+':/tmp/migrate'])
    r=run(['docker','exec',c,'/tmp/migrate','-path','/tmp/stage','-database',f'postgres://{user}@/users?host=/var/run/postgresql&sslmode=disable','up'])
    return r.stderr.strip()

def bootstrap(c,user,package):
    expected={p.name:p.read_bytes() for p in (ROOT/'module/services/store/migrations').glob('*.sql')
              if user=='postgres' or int(p.name.split('_')[0])>135}
    if user!='postgres':expected.update({p.name:p.read_bytes() for p in (ROOT/'module/services/store/baselines/managed-v1').glob('*.sql')})
    actual={p.name:p.read_bytes() for p in (package/'bootstrap/sources/store').glob('*.sql')}
    assert actual==expected,'package SQL does not match the candidate profile'
    run(['docker','cp',str(package),c+':/tmp/package'])
    return replay_bootstrap(c,user)

def replay_bootstrap(c,user):
    result=run(['docker','exec','--user','65532:65532','-e',
        f'CODEFLY_POSTGRES_MIGRATION_CONNECTION=postgres://{user}@/users?host=/var/run/postgresql&sslmode=disable',
        c,'/tmp/package/managed-bootstrap','-package','/tmp/package/bootstrap',
        '-binding','/tmp/package/binding.json','-migrate','/tmp/package/migrate'])
    receipt=json.loads(result.stdout)
    assert receipt['access-committed'],receipt
    return receipt

def catalog(c):
    dump=run(['docker','exec',c,'pg_dump','-U','postgres','--no-owner','--schema-only','--dbname=users']).stdout
    dump=re.sub(r'^\\(?:un)?restrict .*\n','',dump,flags=re.M)
    dump=dump.replace('example_migrator','postgres')
    return dump

def authorities(c):
    result = json.loads(sql(c,"""SELECT json_build_object(
 'relations',(SELECT json_agg(x ORDER BY name) FROM (
 SELECT c.relname name,c.relrowsecurity rls,c.relforcerowsecurity force_rls,
 array_to_string(coalesce(c.relacl,acldefault(CASE WHEN c.relkind='S' THEN 'S' ELSE 'r' END::"char",c.relowner)),',') acl FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relkind IN ('r','p','v','S')) x),
 'functions',(SELECT json_agg(x ORDER BY signature) FROM (
 SELECT p.oid::regprocedure::text signature,p.prosecdef security_definer,r.rolname owner,array_to_string(coalesce(p.proacl,acldefault('f',p.proowner)),',') acl
 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='public') x));""").stdout.replace('example_migrator','postgres'))
    for rows in result.values():
        for row in rows: row['acl']=sorted(row['acl'].split(','))
    return result

def seed_catalog(c):
    remap={}
    for table,key in [('roles','name'),('plans','name'),('email_templates','name'),('data_retention_policies','resource_type')]:
        rows=json.loads(sql(c,f'SELECT json_agg(t) FROM public.{table} t').stdout)
        for row in rows: remap[row['id']]='seed:'+table+':'+row[key]
    result={}
    for table in ['audit_event_types','bootstrap_state','data_retention_policies','email_templates','identity_providers','plan_entitlements','plans','role_permissions','roles']:
        raw=sql(c,f"SELECT coalesce(json_agg(to_jsonb(t)-'created_at'-'updated_at'),'[]') FROM public.{table} t").stdout
        for old,new in remap.items(): raw=raw.replace(old,new)
        result[table]=sorted(json.dumps(row,sort_keys=True) for row in json.loads(raw))
    return result

def migration_command(c,user,*direction):
    return ['docker','exec',c,'/tmp/migrate','-path','/tmp/stage','-database',
            f'postgres://{user}@/users?host=/var/run/postgresql&sslmode=disable',*direction]

def migration_safety(migrate_binary,tests,containers):
    baseline=(ROOT/'module/services/store/baselines/managed-v1/135_managed_baseline.up.sql').read_text()
    for kind,setup,error in [
        ('role','CREATE ROLE app_tenant;','requires absent application roles'),
        ('relation','CREATE TABLE public.existing_data(id int);','requires an empty application database'),
        ('function',"CREATE FUNCTION public.existing_function() RETURNS int LANGUAGE sql AS 'SELECT 1';",'requires absent application functions')]:
        c=start();containers.append(c)
        sql(c,'CREATE ROLE example_migrator LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS CREATEROLE; ALTER DATABASE users OWNER TO example_migrator;')
        sql(c,setup)
        r=sql(c,'BEGIN;\n'+baseline,user='example_migrator',check=False)
        assert r.returncode and error in r.stderr,(kind,r.stderr)
        assert sql(c,"SELECT count(*) FROM pg_roles WHERE rolname='app_job_worker'").stdout.strip()=='0'
        tests.append({'case':'fresh_refuses_existing_'+kind+'_without_partial_roles','passed':True})
        run(['docker','rm','-f','-v',c]);containers.remove(c)
    # A different upgrade actor must not become the endpoint-read policy owner.
    c=start();containers.append(c)
    sql(c,'CREATE ROLE example_migrator LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS CREATEROLE; ALTER DATABASE users OWNER TO example_migrator;')
    sql(c,'BEGIN;'+baseline+'COMMIT;',user='example_migrator')
    sql(c,'BEGIN;'+(ROOT/'module/services/store/migrations/136_explicit_background_rls.up.sql').read_text()+'COMMIT;')
    assert sql(c,"SELECT r.rolname FROM pg_policy p JOIN pg_roles r ON r.oid=p.polroles[1] WHERE p.polname='webhook_subscriptions_migration_owner_read'").stdout.strip()=='example_migrator'
    sql(c,"""INSERT INTO users(uuid,primary_email) VALUES ('10000000-0000-0000-0000-000000000001','one@example.com');
INSERT INTO organizations(id,name,slug,owner_id) VALUES ('20000000-0000-0000-0000-000000000001','Example','example','10000000-0000-0000-0000-000000000001');
INSERT INTO webhook_subscriptions(id,org_id,url,secret_encrypted) VALUES ('20000000-0000-0000-0000-000000000001','20000000-0000-0000-0000-000000000001','https://example.com','synthetic');
BEGIN; SET LOCAL ROLE app_tenant; SET LOCAL app.current_org_id='20000000-0000-0000-0000-000000000001';
SELECT public.sync_webhook_event_subscriptions('20000000-0000-0000-0000-000000000001','20000000-0000-0000-0000-000000000001',ARRAY['saas.auth.login']); COMMIT;""")
    assert sql(c,'SELECT count(*) FROM event_subscriptions').stdout.strip()=='1'
    tests.append({'case':'different_upgrade_actor_preserves_non_bypass_sync_owner_and_endpoint_read_policy','passed':True})
    run(['docker','rm','-f','-v',c]);containers.remove(c)
    for mode in ['failure','interruption']:
        c=start();containers.append(c)
        sql(c,'CREATE ROLE example_migrator LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS CREATEROLE; ALTER DATABASE users OWNER TO example_migrator;')
        with tempfile.TemporaryDirectory(prefix='managed-failure-') as tmp:
            stage=Path(tmp)/'stage';stage.mkdir()
            for f in (ROOT/'module/services/store/baselines/managed-v1').glob('*.sql'):shutil.copy(f,stage/f.name)
            migrate(c,'example_migrator',stage,migrate_binary)
            up=(ROOT/'module/services/store/migrations/136_explicit_background_rls.up.sql').read_text()
            injected=up.replace('GRANT CREATE ON SCHEMA public TO app_control_plane;',
                'GRANT CREATE ON SCHEMA public TO app_control_plane;\n'+('SELECT 1/0;' if mode=='failure' else 'SELECT pg_sleep(30);'),1)
            failure=stage/'136_explicit_background_rls.up.sql';failure.write_text(injected)
            run(['docker','cp',str(failure),c+':/tmp/stage/'+failure.name])
            if mode=='failure':
                r=run(migration_command(c,'example_migrator','up'),check=False)
                assert r.returncode and 'division by zero' in r.stderr,r.stderr
            else:
                process=subprocess.Popen(migration_command(c,'example_migrator','up'),text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                try:
                    for _ in range(200):
                        pid=sql(c,"SELECT pid FROM pg_stat_activity WHERE usename='example_migrator' AND wait_event='PgSleep'").stdout.strip()
                        if pid:break
                        time.sleep(.05)
                    else:raise AssertionError('interruption fixture never reached temporary grant')
                    assert pid.isdigit()
                    sql(c,'SELECT pg_terminate_backend('+pid+');')
                    process.communicate(timeout=15)
                    assert process.returncode
                finally:
                    if process.poll() is None:
                        process.kill();process.communicate(timeout=5)
            assert sql(c,"SELECT version::text||':'||dirty::text FROM schema_migrations").stdout.strip()=='136:true'
            assert sql(c,"SELECT count(*) FROM pg_policy WHERE polname LIKE '%_explicit_rows'").stdout.strip()=='0'
            assert sql(c,"SELECT bool_and(NOT has_schema_privilege(rolname,'public','CREATE')) FROM pg_roles WHERE rolname LIKE 'app_%'").stdout.strip()=='t'
            assert sql(c,"SELECT pg_get_userbyid(proowner) FROM pg_proc WHERE proname='enqueue_job_message'").stdout.strip()=='example_migrator'
            tests.append({'case':'migration_'+mode+'_rolls_back_policies_function_owner_and_temporary_create_grant_leaves_dirty_ledger','passed':True})
        run(['docker','rm','-f','-v',c]);containers.remove(c)

def qualify(c,label,tests):
    def check(name,body,want=None,error=None,user='postgres'):
        r=sql(c,body,user,False)
        if error: assert r.returncode and error in r.stderr,(label,name,r.stderr,r.stdout)
        else: assert not r.returncode and (want is None or r.stdout.strip()==want),(label,name,r.stderr,r.stdout,want)
        tests.append({'profile':label,'case':name,'passed':True})
    # Fixture writes are independent of runtime role checks.
    check('seed_two_owners_and_orgs',"""INSERT INTO users(uuid,primary_email) VALUES
('10000000-0000-0000-0000-000000000001','one@example.com'),('10000000-0000-0000-0000-000000000002','two@example.com');
INSERT INTO organizations(id,name,slug,owner_id) VALUES
('20000000-0000-0000-0000-000000000001','Example One','example-one','10000000-0000-0000-0000-000000000001'),
('20000000-0000-0000-0000-000000000002','Example Two','example-two','10000000-0000-0000-0000-000000000002');
INSERT INTO organization_members(org_id,user_id,role) SELECT id,owner_id,'owner' FROM organizations;
INSERT INTO execution_custody(reference,org_id,owner_id,admission_id,fingerprint,envelope,expires_at)
SELECT '30000000-0000-0000-0000-000000000001',id,owner_id,'example-admission',repeat('a',64),'cfs1:vault-transit:synthetic',now()+interval '5 minutes' FROM organizations WHERE slug='example-one';
INSERT INTO webhook_subscriptions(id,org_id,url,secret_encrypted) SELECT id,id,'https://example.com/hook','synthetic' FROM organizations;
INSERT INTO webhook_deliveries(id,subscription_id,event_id,event_type,payload) SELECT id,id,id,'saas.auth.login','{}' FROM organizations;
""")
    check('request_only_login','CREATE ROLE example_request LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS; GRANT app_tenant TO example_request;')
    tenant="BEGIN; SET LOCAL ROLE app_tenant; SET LOCAL app.current_org_id='20000000-0000-0000-0000-000000000001'; SET LOCAL app.current_user_id='10000000-0000-0000-0000-000000000001'; "
    check('tenant_own_org',tenant+'SELECT count(*) FROM organizations; ROLLBACK;','1')
    check('tenant_cross_org_denied',tenant+"SELECT count(*) FROM organizations WHERE slug='example-two'; ROLLBACK;",'0')
    check('tenant_own_user',tenant+'SELECT count(*) FROM users; ROLLBACK;','1')
    check('custom_guc_cannot_widen',tenant+"SET LOCAL app.bypass='true'; SELECT count(*) FROM users; ROLLBACK;",'1')
    check('request_cannot_assume_control','SET ROLE app_control_plane;',error='42501',user='example_request')
    for role in ROLES[1:]:
        check('tenant_cannot_assume_'+role,'SET ROLE '+role+';',error='42501',user='example_request')
    for table in ['execution_custody','job_messages']:
        check('tenant_no_'+table,tenant+'SELECT count(*) FROM '+table+';',error='42501')
    for role,table,n in [('app_control_plane','users','2'),('app_control_plane','execution_custody','1'),('app_billing_worker','organizations','2'),('app_webhook_worker','webhook_deliveries','2')]:
        check(role+'_cross_scope_'+table,'BEGIN; SET LOCAL ROLE '+role+'; SELECT count(*) FROM '+table+'; ROLLBACK;',n)
    for role,table in [('app_billing_worker','execution_custody'),('app_webhook_worker','users'),('app_job_worker','users'),('app_control_plane','job_messages')]:
        check(role+'_no_'+table,'BEGIN; SET LOCAL ROLE '+role+'; SELECT count(*) FROM '+table+';',error='42501')
    check('preauth_lookup_without_tenant',"BEGIN; SET LOCAL ROLE app_control_plane; SELECT count(*) FROM users WHERE primary_email='two@example.com'; ROLLBACK;",'1')
    check('custody_erase',"BEGIN; SET LOCAL ROLE app_control_plane; WITH x AS (UPDATE execution_custody SET envelope='' RETURNING reference) SELECT count(*) FROM x; ROLLBACK;",'1')
    check('custody_identity_immutable',"BEGIN; SET LOCAL ROLE app_control_plane; UPDATE execution_custody SET admission_id='changed';",error='42501')
    check('webhook_result_update',"BEGIN; SET LOCAL ROLE app_webhook_worker; WITH x AS (UPDATE webhook_deliveries SET http_status=204 RETURNING id) SELECT count(*) FROM x; ROLLBACK;",'2')
    check('webhook_payload_immutable',"BEGIN; SET LOCAL ROLE app_webhook_worker; UPDATE webhook_deliveries SET payload='changed';",error='42501')
    check('tenant_cross_org_write_denied',tenant+"UPDATE organizations SET slug='changed' WHERE slug='example-two'; SELECT count(*) FROM organizations WHERE slug='changed'; ROLLBACK;",'0')
    # Even a credential with inherited membership cannot activate role policies
    # while its current role is app_tenant. Only exact SET ROLE may do so.
    check('no_runtime_ddl',tenant+'CREATE TABLE public.denied(id int);',error='42501')
    check('custody_accidental_tenant_select_still_denied',"BEGIN; GRANT SELECT ON execution_custody TO app_tenant; SET LOCAL ROLE app_tenant; SELECT count(*) FROM execution_custody; ROLLBACK;",'0')
    check('inherited_control_role_cannot_activate_policy',"BEGIN; GRANT app_control_plane TO app_tenant WITH INHERIT TRUE; SET LOCAL ROLE app_tenant; SELECT count(*) FROM execution_custody; ROLLBACK;",'0')
    for role in ROLES[1:]:
        login='example_'+role
        check('dedicated_'+role, 'CREATE ROLE '+login+' LOGIN NOINHERIT; GRANT '+role+' TO '+login+';')
        other='app_control_plane' if role!='app_control_plane' else 'app_job_worker'
        check(role+'_cannot_assume_'+other,'SET ROLE '+other+';',error='42501',user=login)
    check('seed_refresh_sessions',"""INSERT INTO sessions(id,user_id,refresh_token_hash,family_id,org_id,expires_at,idle_expires_at)
SELECT id,owner_id,slug,id,id,now()+interval '1 hour',now()+interval '1 hour' FROM organizations;""")
    check('membership_revocation_is_scoped_and_atomic',tenant+"""DELETE FROM organization_members WHERE org_id='20000000-0000-0000-0000-000000000001'; RESET ROLE;
SELECT count(*) FILTER (WHERE revoked_at IS NOT NULL)::text || ':' || count(*) FILTER (WHERE revoked_at IS NULL)::text FROM sessions; ROLLBACK;""",'1:1')
    check('revocation_rollback_restores_sessions','SELECT count(*) FROM sessions WHERE revoked_at IS NULL;','2')
    check('user_status_revokes_exact_owner',tenant+"""UPDATE users SET status='suspended' WHERE uuid='10000000-0000-0000-0000-000000000001'; RESET ROLE;
SELECT count(*) FILTER (WHERE revoked_at IS NOT NULL)::text || ':' || count(*) FILTER (WHERE revoked_at IS NULL)::text FROM sessions; ROLLBACK;""",'1:1')
    check('managed_control_plane_diagnostic','BEGIN; SET LOCAL ROLE app_control_plane; SELECT public.record_membership_integrity_findings(); ROLLBACK;','0')
    check('billing_projection_update',"""BEGIN; SET LOCAL ROLE app_billing_worker;
INSERT INTO subscriptions(id,org_id,plan_id,status) SELECT id,id,(SELECT id FROM plans WHERE name='free'),'active' FROM organizations;
SELECT count(*) FROM subscriptions; ROLLBACK;""",'2')
    enqueue="public.enqueue_job_message('outbox','tenant','20000000-0000-0000-0000-000000000001',NULL,'example.queue','example.topic','example.source','example-key',NULL,1,decode('7b7d','hex'),'application/json','{}',0::smallint,3,now(),decode(repeat('aa',32),'hex'))"
    check('tenant_guarded_enqueue_then_worker_receipt',tenant+'SELECT inserted FROM '+enqueue+'; SET LOCAL ROLE app_job_worker; SELECT count(*) FROM job_messages; ROLLBACK;','t\n1')
    wrong=enqueue.replace('20000000-0000-0000-0000-000000000001','20000000-0000-0000-0000-000000000002')
    check('tenant_enqueue_wrong_org_denied',tenant+'SELECT * FROM '+wrong+';',error='42501')
    subject=enqueue.replace("'tenant','20000000-0000-0000-0000-000000000001',NULL", "'subject',NULL,'10000000-0000-0000-0000-000000000001'")
    for shape,call,setting in [('tenant',enqueue,'app.current_org_id'),('subject',subject,'app.current_user_id')]:
        check(shape+'_enqueue_valid_context',tenant+'SELECT inserted FROM '+call+'; ROLLBACK;','t',user='example_request')
        check(shape+'_enqueue_missing_context','BEGIN; SET LOCAL ROLE app_tenant; SELECT * FROM '+call+';',error='42501',user='example_request')
        check(shape+'_enqueue_empty_context',tenant+'SET LOCAL '+setting+"=''; SELECT * FROM "+call+';',error='42501',user='example_request')
        check(shape+'_enqueue_wrong_context',tenant+'SELECT * FROM '+call.replace('000000000001','000000000002')+';',error='42501',user='example_request')
    global_enqueue=enqueue.replace("'tenant','20000000-0000-0000-0000-000000000001',NULL", "'global',NULL,NULL")
    check('control_plane_global_outbox',"BEGIN; SET LOCAL ROLE app_control_plane; SELECT inserted FROM "+global_enqueue+'; ROLLBACK;','t')
    check('control_plane_cannot_enqueue_tenant',"BEGIN; SET LOCAL ROLE app_control_plane; SELECT * FROM "+enqueue+';',error='42501')
    check('worker_cross_tenant_enqueue_and_lookup',"BEGIN; SET LOCAL ROLE app_job_worker; SELECT inserted FROM "+enqueue+'; SELECT inserted FROM '+wrong+"; SELECT count(*) FROM job_messages; ROLLBACK;",'t\nt\n2')
    publish="public.publish_domain_event('40000000-0000-0000-0000-000000000001','saas.auth.login','example','example',now(),'1.0','application/json',NULL,decode('7b7d','hex'),'20000000-0000-0000-0000-000000000001','example',NULL,NULL,NULL,NULL,NULL,NULL,1,decode(repeat('bb',32),'hex'))"
    check('tenant_guarded_event_publish',tenant+'SELECT inserted FROM '+publish+'; SET LOCAL ROLE app_job_worker; SELECT count(*) FROM domain_events; ROLLBACK;','t\n1')
    check('tenant_event_cross_org_denied',tenant+'SELECT * FROM '+publish.replace('20000000-0000-0000-0000-000000000001','20000000-0000-0000-0000-000000000002')+';',error='42501')
    sync="public.sync_webhook_event_subscriptions('20000000-0000-0000-0000-000000000001','20000000-0000-0000-0000-000000000001',ARRAY['saas.auth.login'])"
    check('tenant_guarded_webhook_sync',tenant+'SELECT '+sync+'; SET LOCAL ROLE app_job_worker; SELECT count(*) FROM event_subscriptions; ROLLBACK;','1')
    check('tenant_guarded_webhook_remove',tenant+'SELECT '+sync+'; SELECT '+sync.replace("ARRAY['saas.auth.login']","ARRAY[]::text[]")+'; SET LOCAL ROLE app_job_worker; SELECT count(*) FROM event_subscriptions; ROLLBACK;','0')
    check('webhook_sync_missing_org_denied','BEGIN; SET LOCAL ROLE app_tenant; SELECT '+sync+';',error='42501',user='example_request')
    check('webhook_sync_empty_org_denied',tenant+"SET LOCAL app.current_org_id=''; SELECT "+sync+';',error='42501',user='example_request')
    check('webhook_sync_cross_org_denied',tenant+'SELECT '+sync.replace('000000000001','000000000002')+';',error='42501')
    check('webhook_sync_wrong_endpoint_denied',tenant+"SELECT public.sync_webhook_event_subscriptions('20000000-0000-0000-0000-000000000001','20000000-0000-0000-0000-000000000002',ARRAY['saas.auth.login']);",error='42501')
    replay="public.replay_job_message((SELECT id FROM job_messages WHERE replay_of IS NULL),'example-replay',now(),decode(repeat('cc',32),'hex'))"
    check('worker_replay_requires_dead_letter',"BEGIN; SET LOCAL ROLE app_job_worker; SELECT inserted FROM "+enqueue+'; SELECT * FROM '+replay+';',error='55000')
    check('worker_dead_letter_replay_converges',"BEGIN; SET LOCAL ROLE app_job_worker; SELECT inserted FROM "+enqueue+"; UPDATE job_messages SET state='processing',attempt_count=1,lease_owner='example-worker',lease_token='50000000-0000-0000-0000-000000000001',lease_expires_at=now()+interval '1 minute',heartbeat_at=now(); UPDATE job_messages SET state='dead_letter',last_error_code='example.failure',dead_lettered_at=now(),lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,heartbeat_at=NULL; SELECT inserted FROM "+replay+'; SELECT inserted FROM '+replay+'; SELECT count(*) FROM job_messages; ROLLBACK;','t\nt\nf\n2')
    check('tenant_cannot_replay_jobs',tenant+"SELECT * FROM public.replay_job_message('40000000-0000-0000-0000-000000000001','example-replay',now(),decode(repeat('cc',32),'hex'));",error='42501')
    check('tenant_cannot_edit_migration_ledger',tenant+'UPDATE schema_migrations SET version=1;',error='42501')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--migrate',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--fresh-package',type=Path)
    p.add_argument('--upgrade-package',type=Path)
    args=p.parse_args();containers=[];tests=[];bootstrap_receipts=[]
    head=max(int(p.name.split('_')[0]) for p in (ROOT/'module/services/store/migrations').glob('*.up.sql'))
    # Rolling back is counted in migrations, never in version numbers. Versions
    # are deliberately not contiguous — migrations/README.md requires a new
    # version above the target branch's frontier "including gaps", and parallel
    # branches hold numbers that land out of order or never land — so a step
    # count of head-N walks past N the moment any number in between is missing.
    above=lambda version:sum(1 for f in (ROOT/'module/services/store/migrations').glob('*.up.sql') if int(f.name.split('_')[0])>version)
    if bool(args.fresh_package)!=bool(args.upgrade_package):p.error('both packages required together')
    try:
        canonical=start();containers.append(canonical)
        fresh=start();containers.append(fresh)
        if args.fresh_package:
            for c in [canonical,fresh]:
                # External logins inherit their directly granted access group.
                # The group and all application roles remain NOINHERIT.
                sql(c,'CREATE ROLE example_reader LOGIN INHERIT; CREATE ROLE example_writer LOGIN INHERIT;')
        with tempfile.TemporaryDirectory(prefix='managed-rls-stage-') as tmp:
            staged=Path(tmp)/'stage';staged.mkdir()
            # Canonical legacy installation, including additive policy upgrade.
            for f in (ROOT/'module/services/store/migrations').glob('*.sql'):shutil.copy(f,staged/f.name)
            if args.upgrade_package:bootstrap_receipts.append(bootstrap(canonical,'postgres',args.upgrade_package))
            else:migrate(canonical,'postgres',staged,args.migrate)
            tests.append({'case':'canonical_upgrade_to_head','passed':True})
            sql(fresh,'CREATE ROLE example_migrator LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS CREATEROLE; ALTER DATABASE users OWNER TO example_migrator;')
            for f in staged.iterdir():f.unlink()
            for f in (ROOT/'module/services/store/baselines/managed-v1').glob('*.sql'):shutil.copy(f,staged/f.name)
            # Everything the baseline does not already contain, which is the same
            # rule stage.py and bootstrap() state: the baseline installs through
            # 135, so the fresh profile carries every later migration. Naming one
            # version here instead would silently drop the next migration anybody
            # adds from the fresh install, and this equivalence check is exactly
            # what would then report the two profiles as differing.
            for f in (ROOT/'module/services/store/migrations').glob('*.sql'):
                if int(f.name.split('_')[0])>135:shutil.copy(f,staged/f.name)
            if args.fresh_package:bootstrap_receipts.append(bootstrap(fresh,'example_migrator',args.fresh_package))
            else:migrate(fresh,'example_migrator',staged,args.migrate)
            assert sql(fresh,'SELECT version::text || \':\' || dirty::text FROM schema_migrations').stdout.strip()==f'{head}:false'
            tests.append({'case':'non_superuser_non_bypass_install_to_head','passed':True})
            before=catalog(fresh)
            if args.fresh_package:bootstrap_receipts.append(replay_bootstrap(fresh,'example_migrator'))
            else:run(['docker','exec',fresh,'/tmp/migrate','-path','/tmp/stage','-database','postgres://example_migrator@/users?host=/var/run/postgresql&sslmode=disable','up'])
            assert before==catalog(fresh)
            tests.append({'case':'normal_ledger_replay_no_change','passed':True})
            a,b=catalog(canonical),catalog(fresh)
            if a!=b:
                args.output.parent.mkdir(parents=True,exist_ok=True)
                (args.output.parent/'canonical-schema.sql').write_text(a)
                (args.output.parent/'managed-schema.sql').write_text(b)
                raise AssertionError('schema dump differs; inspect retained comparison')
            aa,bb=authorities(canonical),authorities(fresh)
            if aa!=bb:
                args.output.parent.mkdir(parents=True,exist_ok=True)
                (args.output.parent/'canonical-authority.json').write_text(json.dumps(aa,indent=2))
                (args.output.parent/'managed-authority.json').write_text(json.dumps(bb,indent=2))
                raise AssertionError('authority catalog differs')
            tests.append({'case':'canonical_schema_acl_and_definer_owner_equivalence','passed':True})
            assert seed_catalog(canonical)==seed_catalog(fresh),'seed catalog semantics differ'
            tests.append({'case':'seed_natural_keys_values_and_foreign_keys_equivalent','passed':True})
            for c in [canonical,fresh]:
                assert sql(c,"SELECT bool_and(NOT has_schema_privilege(rolname,'public','CREATE') AND NOT has_database_privilege(rolname,'users','CREATE') AND NOT has_database_privilege(rolname,'users','TEMP')) FROM pg_roles WHERE rolname IN ('app_tenant','app_control_plane','app_billing_worker','app_webhook_worker','app_job_worker')").stdout.strip()=='t'
            tests.append({'case':'runtime_roles_no_database_create_temp_or_schema_create','passed':True})
            if args.fresh_package:
                for c in [canonical,fresh]:
                    for role in ROLES:
                        assert sql(c,'SET ROLE '+role+'; SELECT current_user;',user='example_writer').stdout.strip()==role
                        assert '42501' in sql(c,'SET ROLE '+role+';',user='example_reader',check=False).stderr
                    assert '42501' in sql(c,'CREATE TABLE public.denied(id int);',user='example_writer',check=False).stderr
                    assert '42501' in sql(c,'UPDATE schema_migrations SET version=1;',user='example_writer',check=False).stderr
                    owner='postgres' if c==canonical else 'example_migrator'
                    for login in ['example_reader','example_writer']:
                        assert '42501' in sql(c,'SET ROLE '+owner+';',user=login,check=False).stderr
                tests.append({'case':'managed_access_reconciler_exact_runtime_role_assumption_and_ledger_ddl_denial','passed':True})
            # Exercise the declared legacy rollback using the normal ledger.
            # Packages stage their immutable sources elsewhere; copy the same
            # source bytes for the migration CLI's explicit local down test.
            if args.upgrade_package:
                run(['docker','cp',str(ROOT/'module/services/store/migrations'),canonical+':/tmp/stage'])
                run(['docker','cp',str(args.migrate),canonical+':/tmp/migrate'])
            # Down to 135, not down one step: the case is about rolling back the
            # explicit-policies upgrade, and every migration added after it has
            # to come off first for that to be what actually happens.
            run(migration_command(canonical,'postgres','down',str(above(135))))
            assert sql(canonical,"SELECT version::text||':'||dirty::text FROM schema_migrations").stdout.strip()=='135:false'
            assert sql(canonical,"SELECT count(*) FROM pg_policy WHERE polname LIKE '%_explicit_rows'").stdout.strip()=='0'
            assert sql(canonical,"SELECT bool_and(NOT has_schema_privilege(rolname,'public','CREATE')) FROM pg_roles WHERE rolname LIKE 'app_%'").stdout.strip()=='t'
            run(migration_command(canonical,'postgres','up'))
            assert catalog(canonical)==a
            tests.append({'case':'legacy_rollback_and_reapply_preserves_schema_and_runtime_ddl_denial','passed':True})
            # Legacy keeps BYPASSRLS; prove explicit policies are sufficient after
            # a separately authorized fixture-only attribute reduction.
            for role in ROLES[1:]:sql(canonical,'ALTER ROLE '+role+' NOBYPASSRLS;')
            for c,label in [(fresh,'fresh'),(canonical,'legacy_after_attribute_reduction')]:
                assert sql(c,"SELECT bool_and(NOT rolbypassrls AND NOT rolsuper AND NOT rolcanlogin AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolinherit) FROM pg_roles WHERE rolname IN ('app_tenant','app_control_plane','app_billing_worker','app_webhook_worker','app_job_worker')").stdout.strip()=='t'
                qualify(c,label,tests)
                if args.fresh_package:
                    scope="BEGIN; SET LOCAL app.current_org_id='20000000-0000-0000-0000-000000000001'; SET LOCAL app.current_user_id='10000000-0000-0000-0000-000000000001'; "
                    assert sql(c,scope+'SELECT count(*) FROM organization_authorization_revisions; ROLLBACK;',user='example_reader').stdout.strip()=='1'
                    assert sql(c,scope+"SELECT count(*) FROM organization_authorization_revisions WHERE org_id='20000000-0000-0000-0000-000000000002'; ROLLBACK;",user='example_reader').stdout.strip()=='0'
                    assert sql(c,scope+'SELECT count(*) FROM execution_custody; ROLLBACK;',user='example_reader').stdout.strip()=='0'
                    assert '42501' in sql(c,scope+'UPDATE organization_authorization_revisions SET revision=revision+1;',user='example_reader',check=False).stderr
                    assert '42501' in sql(c,'SELECT count(*) FROM organization_authorization_revisions;',user='example_writer',check=False).stderr
                    memberships=json.loads(sql(c,"""SELECT json_agg(x ORDER BY member,granted) FROM (
SELECT member.rolname member,granted.rolname granted,a.inherit_option,a.set_option,a.admin_option
FROM pg_auth_members a JOIN pg_roles member ON member.oid=a.member JOIN pg_roles granted ON granted.oid=a.roleid
WHERE member.rolname IN ('example_reader','example_writer','example_ro','example_rw')) x""").stdout)
                    assert len(memberships)==7,memberships
                    for edge in memberships:
                        assert edge['set_option'] and not edge['admin_option'],edge
                        assert edge['inherit_option']==(edge['member'] in ['example_reader','example_writer']),edge
                    tests.append({'profile':label,'case':'ambient_reader_inherits_select_with_tenant_isolation_and_no_write_or_custody_visibility','passed':True})
                    tests.append({'profile':label,'case':'writer_group_does_not_inherit_application_roles_and_requires_explicit_set_role','passed':True,'memberships':memberships})
            if args.fresh_package:
                run(['docker','cp',str(staged),fresh+':/tmp/stage'])
                run(['docker','cp',str(args.migrate),fresh+':/tmp/migrate'])
            # Later migrations may legitimately add and remove their own policies.
            # Snapshot the policy inventory at 136, immediately before the guarded
            # downgrade, so its refusal still proves that it removed no policy.
            if above(136):
                run(migration_command(fresh,'example_migrator','down',str(above(136))))
            assert sql(fresh,"SELECT version::text||':'||dirty::text FROM schema_migrations").stdout.strip()=='136:false'
            policy_before=sql(fresh,'SELECT count(*) FROM pg_policy').stdout
            r=run(migration_command(fresh,'example_migrator','down','1'),check=False)
            assert r.returncode and 'background policy rollback requires' in r.stderr,r.stderr
            assert sql(fresh,'SELECT count(*) FROM pg_policy').stdout==policy_before
            assert sql(fresh,"SELECT version::text||':'||dirty::text FROM schema_migrations").stdout.strip()=='135:true'
            tests.append({'case':'managed_rollback_refuses_before_any_policy_removal_and_leaves_dirty_ledger','passed':True})
        migration_safety(args.migrate,tests,containers)
        receipt={'passed':True,'source':run(['git','rev-parse','HEAD'],cwd=ROOT).stdout.strip(),'dirty':bool(run(['git','status','--porcelain'],cwd=ROOT).stdout),'postgres_image':IMAGE,'server_version':sql(fresh,'SHOW server_version').stdout.strip(),'tests':tests,'bootstrap_receipts':bootstrap_receipts,'local_only':True,'managed_calls':0,'migrate_binary_sha256':hashlib.sha256(args.migrate.read_bytes()).hexdigest()}
        args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(receipt,indent=2)+'\n')
        print(json.dumps({'passed':True,'tests':len(tests),'output':str(args.output)}))
    finally:
        for c in reversed(containers):run(['docker','rm','-f','-v',c],check=False)
if __name__=='__main__':main()
