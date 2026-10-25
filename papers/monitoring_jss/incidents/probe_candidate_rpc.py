"""Read-only public JSON-RPC availability probe; never sends transactions."""
import concurrent.futures, datetime, hashlib, json, pathlib, time, urllib.request
ROOT=pathlib.Path(__file__).resolve().parent
PROBES=[
 ('ethereum_chain_id','https://ethereum-rpc.publicnode.com','eth_chainId',[]),
 ('beanstalk_receipt','https://ethereum-rpc.publicnode.com','eth_getTransactionReceipt',['0xcd314668aaa9bbfebaf1a0bd2b6553d01dd58899c508d4729fa7311dc5d33ad7']),
 ('bsc_chain_id','https://bsc-dataseed.bnbchain.org','eth_chainId',[]),
 ('bsc_receipt','https://bsc-dataseed.bnbchain.org','eth_getTransactionReceipt',['0xebf83628ba893d35b496121fb8201666b8e09f3cbadf0e269162baa72efe3b8b']),
]
def probe(p):
 name,url,method,params=p; record={'probe':name,'endpoint':url,'method':method,'params':params,'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()};t=time.perf_counter()
 payload=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode()
 try:
  request=urllib.request.Request(url,data=payload,headers={'Content-Type':'application/json'},method='POST')
  with urllib.request.urlopen(request,timeout=12) as response: raw=response.read();record['http_status']=response.status
  parsed=json.loads(raw);record['response']=parsed;record['response_sha256']=hashlib.sha256(raw).hexdigest()
  if parsed.get('result') is not None:
   path=ROOT/(name+'_raw.json');path.write_bytes(raw);record['raw_path']=path.name
  record['success']=parsed.get('result') is not None and 'error' not in parsed
 except Exception as exc:record.update(success=False,error_type=type(exc).__name__,error=str(exc))
 record['elapsed_seconds']=time.perf_counter()-t;return record
if __name__=='__main__':
 with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:results=list(pool.map(probe,PROBES))
 (ROOT/'rpc_availability_probe.json').write_text(json.dumps(results,indent=2)+'\n')
 for r in results:print(r['probe'],r['success'],r.get('error',r.get('response')))
