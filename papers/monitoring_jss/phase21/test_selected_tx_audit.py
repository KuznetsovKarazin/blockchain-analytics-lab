import importlib.util
from pathlib import Path

P=Path(__file__).with_name('selected_tx_audit.py')
spec=importlib.util.spec_from_file_location('phase21',P)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

def test_core_counts_and_union():
    cores={'a':'0xabc','b':'0xdef'}
    x=[('0xabc',20,0),('0xabc',20,0),('0xdef',20,0),
       ('0xdef',20,1),('0xbeef',20,2),('0xabc',21,2)]
    logs,unique,union=mod.tally_selected(x,cores)
    assert logs=={'a':3,'b':2}
    assert unique=={'a':2,'b':2}
    assert union==3

def test_empty_and_zero():
    assert mod.tally_selected([],{'a':'0xabc'})==({'a':0},{'a':0},0)

def test_case_normalization():
    x=[('0xABc',1,2),('0xabc',1,2)]
    a,b,c=mod.tally_selected(x,{'a':'0xabc'})
    assert (a['a'],b['a'],c)==(2,1,1)