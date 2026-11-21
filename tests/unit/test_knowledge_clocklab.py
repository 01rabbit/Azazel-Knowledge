"""Lab contract boundaries; production v1 is exercised by its unchanged suite."""
from dataclasses import replace
import json
import pytest
from nacl.signing import VerifyKey
# Stable api deliberately has no lab contract; candidate CI requires this
# module explicitly before collecting, so a missing candidate cannot pass by skip.
ClockContract = pytest.importorskip(
    "azazel_fabric.knowledge_context_clocklab",
    reason="clocklab tests require the explicit candidate Fabric profile",
).ClockContract
from azazel_knowledge.api.knowledge_clock_health import LocalClockHealth
from azazel_knowledge.core.clock import parse_rfc3339, to_rfc3339
from datetime import timedelta
from _api_support import make_client
from test_knowledge_context_route import _configure, _request

class Health:
    def __init__(self, fail_at=999): self.calls=0;self.fail_at=fail_at
    def check(self, contract):
        self.calls+=1
        if self.calls>=self.fail_at: raise ValueError('health lost')

@pytest.mark.parametrize('delta,status', [(5000,200),(5001,503),(-5000,200)])
def test_signed_v2_clock_boundary(tmp_path, delta, status):
    client,settings,*_=make_client(tmp_path)
    signer=_configure(settings);c=ClockContract(5000);h=Health()
    settings.knowledge_context_transport=replace(settings.knowledge_context_transport,clock_contract=c,clock_health=h)
    body=_request();body.update(schema_version='knowledge-context-request/v2',contract_id=c.contract_id)
    body['requested_at']=to_rfc3339(parse_rfc3339(body['requested_at'])+timedelta(microseconds=delta))
    r=client.post('/v1/knowledge-context',json=body)
    assert r.status_code==status
    if status==200:
        raw=r.content;VerifyKey(signer.public_key).verify(b'azazel-nexus/knowledge-context-envelope/v2\0'+raw[64:],raw[:64])
        d=json.loads(raw[64:]);assert d['schema'].endswith('/2')
        assert d['payload']['contract_id']==c.contract_id
        assert d['payload']['schema_version']=='knowledge-context-response/v2'
        assert d['expires_at']==d['payload']['expires_at']
        assert h.calls==2

@pytest.mark.parametrize('fail_at',[1,2])
def test_health_failure_before_generation_or_signing(tmp_path,fail_at):
    client,settings,*_=make_client(tmp_path);_configure(settings);c=ClockContract(5000)
    settings.knowledge_context_transport=replace(settings.knowledge_context_transport,clock_contract=c,clock_health=Health(fail_at))
    body=_request();body.update(schema_version='knowledge-context-request/v2',contract_id=c.contract_id)
    assert client.post('/v1/knowledge-context',json=body).status_code==503

def test_mixed_policy_and_version_fail_closed(tmp_path):
    client,settings,*_=make_client(tmp_path);_configure(settings);body=_request();c=ClockContract(5000)
    body.update(schema_version='knowledge-context-request/v2',contract_id=c.contract_id)
    assert client.post('/v1/knowledge-context',json=body).status_code==422
    settings.knowledge_context_transport=replace(settings.knowledge_context_transport,clock_contract=c,clock_health=Health())
    assert client.post('/v1/knowledge-context',json=_request()).status_code==422
    body['contract_id']=ClockContract().contract_id
    assert client.post('/v1/knowledge-context',json=body).status_code==422

def local_health():
    c=ClockContract(5000);clock={'mono':2_000_000_000,'wall':12_000_000_000}
    d={'schema':'azazel-clocklab-health/1','boot_id':'boot','sample_boottime_ns':1_000_000_000,
       'sample_wall_ns':11_000_000_000,'error_bound_us':1000,'step_counter':0,'contract_id':c.contract_id}
    h=LocalClockHealth('/run/clock.json',boottime=lambda:clock['mono'],wall=lambda:clock['wall'],boot_id=lambda:'boot')
    h._read=lambda:dict(d)
    return c,h,clock,d

@pytest.mark.parametrize('kind',['age','step','error','boot','counter','policy'])
def test_local_health_bounds_and_latch(kind):
    c,h,clock,d=local_health();h.check(c)
    if kind=='age':clock.update(mono=6_000_000_000,wall=16_000_000_000)
    elif kind=='step':clock['wall']+=3_000_000
    elif kind=='error':d['error_bound_us']=1001
    elif kind=='boot':d['boot_id']='other'
    elif kind=='counter':d['step_counter']=1
    else:d['contract_id']=ClockContract().contract_id
    with pytest.raises(ValueError):h.check(c)
    c2,h2,_,_=local_health();h._read=h2._read
    with pytest.raises(ValueError):h.check(c)


def test_technique_v2_uses_same_signed_policy(tmp_path):
    from test_knowledge_attack_technique import _serve
    client,signer,settings=_serve(tmp_path)
    c=ClockContract(5000)
    settings.knowledge_context_transport=replace(settings.knowledge_context_transport,clock_contract=c,clock_health=Health())
    body=_request();body.update(schema_version='knowledge-context-request/v2',contract_id=c.contract_id)
    body['entities']=[{'entity_type':'attack-technique/v1','value':'T1110'}]
    r=client.post('/v1/knowledge-context',json=body)
    assert r.status_code==200
    VerifyKey(signer.public_key).verify(b'azazel-nexus/knowledge-context-envelope/v2\0'+r.content[64:],r.content[:64])
    d=json.loads(r.content[64:]);assert d['payload']['contract_id']==c.contract_id
    assert d['payload']['facts'][0]['predicate']=='coverage'


@pytest.mark.parametrize('delta_ns,accepted',[
    (-1_000_001,False),(-1_000_000,True),(1_000_000,True),(1_000_001,False),
    (-1_999_000,False),(1_999_000,False),
])
def test_one_ms_local_step_boundary_and_publication_counterexample(delta_ns,accepted):
    c,h,clock,d=local_health();clock['mono']=d['sample_boottime_ns'];clock['wall']=d['sample_wall_ns']+delta_ns
    if accepted:h.check(c)
    else:
        with pytest.raises(ValueError,match='step'):h.check(c)
        clock['wall']=d['sample_wall_ns']
        with pytest.raises(ValueError,match='latched'):h.check(c)


@pytest.mark.parametrize("old_id", [
    "sha256:cf12dddea0953a51e8fb91b4524b6064118d1405a92601f3f89a8a8f28603de5",
    "sha256:62281d081b7905bc4447d2f920bdb504e88edfdc86300a01bcf76d6a80246e21",
])
def test_previous_policy_id_cannot_be_signed_under_new_contract(tmp_path,old_id):
    client,settings,*_=make_client(tmp_path);_configure(settings);c=ClockContract(5000)
    settings.knowledge_context_transport=replace(settings.knowledge_context_transport,clock_contract=c,clock_health=Health())
    body=_request();body.update(schema_version='knowledge-context-request/v2',contract_id=old_id)
    assert client.post('/v1/knowledge-context',json=body).status_code==422


@pytest.mark.parametrize("old_schema", ["azazel-clocklab-policy/1", "azazel-clocklab-policy/2"])
def test_old_fabric_policy_revision_is_rejected_even_for_same_type(monkeypatch,old_schema):
    c,h,_,_=local_health()
    monkeypatch.setattr(ClockContract,'as_dict',lambda self:{'schema':old_schema})
    with pytest.raises(ValueError,match='revision'):h.check(c)
