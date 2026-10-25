"""Read-only follow-up to a single confirmed incident receipt; not a corpus."""
import concurrent.futures,json
from probe_candidate_rpc import probe,ROOT
TX='0xebf83628ba893d35b496121fb8201666b8e09f3cbadf0e269162baa72efe3b8b'
BH='0x4bb3dce2d2811c0734ab08c27c8173da377c045cefe20b117443b08eebd2e449'
ENDPOINT='https://bsc-dataseed.bnbchain.org'
PROBES=[('bsc_block',ENDPOINT,'eth_getBlockByHash',[BH,False]),('bsc_tx',ENDPOINT,'eth_getTransactionByHash',[TX]),('bsc_logs',ENDPOINT,'eth_getLogs',[{'blockHash':BH,'address':'0x0000000000000000000000000000000000002000'}]),('bsc_trace',ENDPOINT,'debug_traceTransaction',[TX,{'tracer':'callTracer','timeout':'5s'}])]
if __name__=='__main__':
 with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:results=list(pool.map(probe,PROBES))
 (ROOT/'bsc_detail_probe.json').write_text(json.dumps(results,indent=2)+'\n')
 for r in results:print(r['probe'],r['success'],r.get('error',r.get('response',{}).get('error')))
