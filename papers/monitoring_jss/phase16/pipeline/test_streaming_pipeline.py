"""Synthetic Arrow fixtures only. No archive acquisition or historical row reads."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
import numpy as np
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq
import streaming_pipeline as p

A='0x'+'a'*40
B='0x'+'b'*40
TOKEN='0x'+'c'*40
TRANSFER='0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'
def h(n):return '0x'+f'{n:064x}'
def schema(kind):
 cols={'blocks':p.BLOCK_COLUMNS,'logs':p.LOG_COLUMNS,'transactions':p.TX_COLUMNS}[kind]
 return pa.schema([(k,pa.timestamp('ms') if k in ('timestamp','block_timestamp') else pa.int64() if k in ('number','block_number','transaction_index','log_index','receipt_status','transaction_count') else pa.list_(pa.string()) if k=='topics' else pa.string()) for k in cols])
class Reader:
 def __init__(self,kind,rows,key='synthetic'):
  self.kind=kind;self.source={'key':key};self.table=pa.Table.from_pylist(rows,schema=schema(kind));self.schema=self.table.schema
  sink=pa.BufferOutputStream();pq.write_table(self.table,sink,row_group_size=1);self.file=pq.ParquetFile(pa.BufferReader(sink.getvalue()));self.metadata=self.file.metadata;self.reads=[]
 def read_row_group(self,i,cols):
  self.reads.append((i,tuple(cols)));return self.file.read_row_group(i,columns=cols)
 def iter_row_groups(self,cols):
  for i in range(self.metadata.num_row_groups):yield i,self.read_row_group(i,cols)
 def manifest(self):return {'source':self.source,'row_count_metadata':self.metadata.num_rows,'reads':[list(x) for x in self.reads]}
def fixture(day='2022-02-19',selected=True,address=A):
 stamp=p.day_start(day);block=1000+(int(day[-2:]))*10
 blocks=[{'number':block,'hash':h(block),'parent_hash':h(block-1),'timestamp':stamp//1000000+1000,'transaction_count':2}]
 tx=[{'hash':h(block*10+i),'transaction_index':i,'block_hash':h(block),'block_number':block,'block_timestamp':stamp//1000000+1000,'receipt_status':1} for i in range(2)]
 common={'transaction_index':0,'transaction_hash':h(block*10),'block_number':block,'block_hash':h(block),'block_timestamp':stamp//1000000+1000}
 logs=[{**common,'address':address if selected else B,'topics':[],'data':'0x','log_index':0},
       {**common,'address':TOKEN,'topics':[TRANSFER,'0x'+'0'*24+address[2:],'0x'+'0'*24+B[2:]],'data':'0x'+f'{2**220+19:064x}','log_index':1},
       {**common,'transaction_index':1,'transaction_hash':h(block*10+1),'address':B,'topics':None,'data':None,'log_index':2}]
 readers={kind:[Reader(kind,rows,kind+'-part')] for kind,rows in [('blocks',blocks),('transactions',tx),('logs',logs)]}
 headers=p.check_headers(readers['blocks'][0].table,day,pa,pc,np)
 pred={'block_number':block-1,'block_hash':h(block-1),'parent_hash':h(block-2),'event_time_ns':stamp-1000,'transaction_count':0}
 succ={'block_number':block+1,'block_hash':h(block+1),'parent_hash':h(block),'event_time_ns':stamp+p.DAY_NS+1000,'transaction_count':0}
 return readers,headers,pred,succ
LIMITS={'max_transaction_rows_per_day':100,'max_log_rows_per_day':100,'max_selected_transactions_per_case_day':100,'max_selected_logs_per_day':100}
class Tests(unittest.TestCase):
 def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
 def tearDown(self):self.tmp.cleanup()
 def prepare(self,day='2022-02-19',selected=True,configs=None,output=None):
  readers,headers,pred,succ=fixture(day,selected)
  return p.prepare_day(day,readers,headers,pred,succ,configs or {'a':{'population_addresses':[A]},'z':{'population_addresses':[TOKEN]}},output or self.root/day,pa,pc,np,LIMITS)
 def test_all_emitter_expansion_and_two_cases(self):
  out=self.prepare();self.assertEqual(len(out['cases']['a']['bundles']),1)
  self.assertEqual(len(out['cases']['a']['bundles'][0]['logs']),2)
  self.assertEqual(out['cases']['a']['selected_transactions'][0]['transaction_hash'],out['cases']['z']['selected_transactions'][0]['transaction_hash'])
  self.assertFalse(out['transfer_decoding_performed']);scan=json.loads((self.root/'2022-02-19'/'scan.json').read_bytes())
  self.assertEqual(scan['all_log_identity_rows'],3);self.assertEqual(len(scan['all_address_row_groups']),3);self.assertEqual(len(scan['all_log_hash_row_groups']),3)
  self.assertFalse(scan['nonselected_topics_and_data_validated'])
 def test_empty_selection_is_covered(self):
  out=self.prepare(selected=False,configs={'a':{'population_addresses':[A]}});self.assertEqual(out['cases']['a']['bundles'],[])
  self.assertEqual(json.loads((self.root/'2022-02-19'/'scan.json').read_bytes())['all_log_identity_rows'],3)
 def test_exact_large_amount(self):
  bundle=self.prepare()['cases']['a']['bundles'][0]
  obs=p.observe(bundle['transaction'],bundle['logs'],[A],bundle['archived_core_log_count'],'0'*64,'1'*64,dataset_execution_status=1)
  self.assertEqual(obs['token_flows'][0]['external_out_raw'],str(2**220+19))
 def test_failed_transaction_with_logs_rejected(self):
  rs,hs,_,_=fixture();tx=rs['transactions'][0].table;tx=tx.set_column(tx.schema.get_field_index('receipt_status'),'receipt_status',pa.array([0,1],type=pa.int64()))
  tx=p.check_transactions(tx,hs,'2022-02-19',pa,pc,np)
  with self.assertRaisesRegex(ValueError,'failed transaction'):p.check_log_identities(rs['logs'][0].table,hs,tx,'2022-02-19',pa,pc,np)
 def test_missing_transaction_row_rejected(self):
  rs,hs,_,_=fixture()
  with self.assertRaisesRegex(ValueError,'counts differ'):p.check_transactions(rs['transactions'][0].table.slice(0,1),hs,'2022-02-19',pa,pc,np)
 def test_missing_intermediate_log_rejected(self):
  rs,hs,_,_=fixture();tx=p.check_transactions(rs['transactions'][0].table,hs,'2022-02-19',pa,pc,np);ls=rs['logs'][0].table
  ls=ls.set_column(ls.schema.get_field_index('log_index'),'log_index',pa.array([0,2,3],type=pa.int64()))
  with self.assertRaisesRegex(ValueError,'gapped source'):p.check_log_identities(ls,hs,tx,'2022-02-19',pa,pc,np)
 def test_null_address_rejected(self):
  rs,_,_,_=fixture();ls=rs['logs'][0].table;ls=ls.set_column(ls.schema.get_field_index('address'),'address',pa.array([None,TOKEN,B]))
  with self.assertRaisesRegex(ValueError,'null required'):p.normalize_table(ls,'logs',pa,pc)
 def test_missing_day_and_bad_boundary_rejected(self):
  rs,hs,pred,succ=fixture();succ['event_time_ns']=p.day_start('2022-02-19')+2000000000
  with self.assertRaisesRegex(ValueError,'UTC boundary'):p.prepare_day('2022-02-19',rs,hs,pred,succ,{'a':{'population_addresses':[A]}},self.root/'bad',pa,pc,np,LIMITS)
 def test_empty_log_projection(self):
  r=Reader('logs',[]);table,groups=p.projection([r],p.LOG_ID_COLUMNS,pa);self.assertEqual(len(table),0)
 def window(self):
  cfg=json.loads((p.PAPER/'phase16'/'protocol'/'configs'/'lifi.json').read_bytes());cfg['population_addresses']=[A]
  cfgpath=self.root/'config.json';p.put(cfgpath,cfg);prepared=[];paths=[]
  for d in p.driver.expected_days(cfg):
   prepared.append(self.prepare(d,selected=(d==p.driver.expected_days(cfg)[0]),configs={cfg['case_id']:cfg}));paths.append(self.root/d/'prepared.json')
  selection=p.selection_for_case(cfg,p.file_sha(cfgpath),prepared);selsha=__import__('hashlib').sha256(p.canonical(selection)+b'\n').hexdigest()
  audit={'schema_version':'fixed_address_source_audit_v1','status':'PASS','config_sha256':p.file_sha(cfgpath),'selection_manifest_sha256':selsha,'tier':cfg['source_tier'],'cross_day_header_links_checked':True,'endpoint_anchors_checked':True,'days':[]}
  for prep in prepared:
   cs=prep['cases'][cfg['case_id']]['selected_transactions'];audit['days'].append({'day_utc':prep['day_utc'],'status':'COVERED','selected_transactions':len(cs),'core_log_count':sum(x['archived_core_log_count'] for x in cs),**{k:prep[k] for k in p.driver.COVERAGE_HASHES},**{k:True for k in p.driver.COVERAGE_CHECKS}})
  ap=self.root/'synthetic_audit.json';p.put(ap,audit);return cfgpath,cfg,paths,ap
 def test_full30day_assembly_passes_frozen_driver(self):
  cp,cfg,paths,ap=self.window();out=p.assemble_case(cp,cfg,paths,ap,p.file_sha(ap),self.root/'observations');self.assertEqual(out['status'],'COMPLETE_OBSERVATIONS_NOT_SCORED')
  manifest=json.loads((self.root/'observations'/'manifest.json').read_bytes());self.assertEqual(len(manifest['days']),30);self.assertEqual(manifest['days'][1]['bytes'],0)
 def test_postaudit_payload_mutation_rejected(self):
  cp,cfg,paths,ap=self.window();prep=json.loads(paths[0].read_bytes());prep['cases'][cfg['case_id']]['bundles'][0]['logs'][1]['data']='0x'+'0'*64;p.put(paths[0],prep)
  with self.assertRaisesRegex(ValueError,'audited prepared bundles changed'):p.assemble_case(cp,cfg,paths,ap,p.file_sha(ap),self.root/'bad-output')
 def test_unfrozen_reuse_rejected(self):
  with self.assertRaisesRegex(ValueError,'frozen source expectation'):p.validate_reuse({'x':{}},{},[{'key':'x'}],self.root)
 def test_bound_reuse_and_runtime_mismatch(self):
  source={'key':'x','size_bytes':9,'etag_opaque':'"etag"'};receipt={'source_key':'x','sha256':'a'*64,'size_bytes':9,'etag_opaque':'"etag"','expected_archive_sha256':'b'*64,'expected_original_member_name':'logs.parquet'}
  rp=self.root/'receipt.json';p.put(rp,receipt)
  expectations={'x':{k:receipt[k] for k in ('sha256','size_bytes','etag_opaque')}};expectations['x']['acquisition_receipt']={'path':'receipt.json','sha256':p.file_sha(rp)}
  runtime={'x':{'path':'/synthetic/never-read',**{k:receipt[k] for k in ('source_key','sha256','size_bytes','etag_opaque')}}}
  p.validate_reuse(runtime,expectations,[source],self.root)
  retained={'schema_version':'phase16_retained_original_source_reuse_expectations_v1','objects':[{**receipt,'expected_whole_object_sha256':receipt['sha256']}]};p.validate_reuse_expectations_binding(expectations,retained,self.root)
  runtime['x']['sha256']='c'*64
  with self.assertRaisesRegex(ValueError,'runtime reuse differs'):p.validate_reuse(runtime,expectations,[source],self.root)
 def test_execution_wrapper_and_mutation(self):
  plan=self.root/'plan.json';protocol=self.root/'protocol.json';extra=self.root/'extra.py';p.put(plan,{'synthetic':True});p.put(protocol,{'synthetic':True});extra.write_text('synthetic only')
  repo=Path('/');files=[Path(p.__file__).resolve(),p.PAPER/'phase16'/'collector'/'range_collector.py',extra]
  gate={'schema_version':'article2_phase16_bound_source_execution_gate_v1','status':'ROOT_ACCEPTED_AS_PART_OF_DECLARED_MEASUREMENT','source_plan':{'path':'plan.json','sha256':p.file_sha(plan)},'measurement_protocol':{'path':'protocol.json','sha256':p.file_sha(protocol)},'execution_source_bindings':[{'path':str(x.relative_to(repo)),'sha256':p.file_sha(x)} for x in files]}
  gp=self.root/'gate.json';p.put(gp,gate);freeze={'gate_bindings':{'source_plan':{'path':'gate.json','sha256':p.file_sha(gp)}}}
  p.validate_execution_gate(freeze,self.root,repo,p.file_sha(plan));extra.write_text('changed')
  with self.assertRaisesRegex(ValueError,'execution source changed'):p.validate_execution_gate(freeze,self.root,repo,p.file_sha(plan))
if __name__=='__main__':unittest.main()
