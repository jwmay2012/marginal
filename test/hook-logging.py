#!/usr/bin/env python3
"""Run the actual hook with public dummy Secret canaries and no cluster access."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CANARY = 'MARGINAL_DUMMY_PRIVATE_KEY_CANARY_20260912'
recipe = {'metadata': {'name': 'reload', 'namespace': 'marginal'}, 'spec': {
    'apiVersion': 'v1', 'kind': 'Secret', 'jobTemplates': [
        {'name': name, 'executeHookOnEvent': ['Added', 'Modified'],
         'uniqueKey': '.data.private_key', 'env': '{}',
         'spec': {'template': {'spec': {'containers': [{'name': 'test', 'image': 'fixture'}]}}}}
        for name in ['first', 'second']]}}


def secret(name):
    return {'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {
        'name': name, 'namespace': 'certificates', 'uid': name, 'resourceVersion': '17',
        'annotations': {'embedded': CANARY}}, 'data': {'private_key': CANARY}}


def event(obj, binding='reload'):
    return {'type': 'Event', 'binding': binding, 'watchEvent': 'Modified', 'object': obj}


with tempfile.TemporaryDirectory(prefix='marginal-logging-test-') as directory:
    tmp = Path(directory)
    fake = tmp / 'kubectl'
    fake.write_text('''#!/usr/bin/env python3
import json,os,pathlib,sys
args=sys.argv[1:]
if 'marginaljobs.marginal.flatheadmill.com' in args:
    print((pathlib.Path(os.environ['MARGINAL_TEST_DIR'])/'recipes.json').read_text())
elif 'job' in args and 'get' in args:
    print(json.dumps({'status':{'active':1}}))
else:
    print('unexpected kubectl call',file=sys.stderr)
    sys.exit(99)
''')
    fake.chmod(0o755)
    (tmp / 'recipes.json').write_text(json.dumps({'items': [recipe]}))

    def run(label, contexts, debug=False):
        (tmp / 'context.json').write_text(json.dumps(contexts))
        env = dict(os.environ, PATH=str(tmp)+os.pathsep+os.environ['PATH'],
                   BINDING_CONTEXT_PATH=str(tmp/'context.json'), MARGINAL_TEST_DIR=str(tmp))
        env.pop('MARGINAL_DUMP_BINDING', None)
        if debug:
            env['MARGINAL_DUMP_BINDING'] = '1'
        result = subprocess.run(['zshctl', str(ROOT/'hooks'/'hook')], env=env,
                                capture_output=True, text=True)
        assert CANARY not in result.stdout + result.stderr, f'{label}: Secret canary leaked'
        assert result.returncode == 0, f'{label}: unexpected failure: {result.stderr}'
        if debug:
            assert 'private_key' not in result.stdout and 'embedded' not in result.stdout
        print('ok - '+label)

    run('batched Secret events and multiple templates never log values', [event(secret('first')), event(secret('second'))])
    run('mixed Secret and Job events never print the prior object', [event(secret('first')),
        event({'kind':'Job','status':{'active':1}}, 'marginal-managed-jobs'), event(secret('last'))])
    run('synchronization objects do not expose template work-key values', [
        {'type':'Synchronization','binding':'reload','objects':[{'object':secret('first')},{'object':secret('second')}]}])
    run('debug output excludes data and embedded annotations', [event(secret('first')), event(secret('second'))], debug=True)
