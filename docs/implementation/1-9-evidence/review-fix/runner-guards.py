import contextlib, io, json, os, runpy, subprocess, tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
runner=Path('docs/implementation/1-9-evidence/verification-runner.py').resolve()
with tempfile.TemporaryDirectory(prefix='story19-runner-guards-') as directory:
    root=Path(directory);deps=root/'custom-deps';(deps/'puppeteer-core').mkdir(parents=True);(deps/'axe-core').mkdir()
    (deps/'puppeteer-core/package.json').write_text(json.dumps({'main':'entry.js'}));(deps/'puppeteer-core/entry.js').write_text('');(deps/'axe-core/axe.min.js').write_text('')
    cert=root/'custom-certutil';cert.write_text('#!/bin/sh\nexit 0\n');cert.chmod(0o700)
    def check(selection, success, expected=None, browser=False):
        calls=[];output=io.StringIO();env={'STORY19_CHECKS':selection,'STORY19_EVIDENCE_PHASE':'guard','VW_UI_DEPS':str(deps),'CERTUTIL':str(cert)}
        if browser is False:env['VW_UI_DEPS']=str(root/'missing')
        cwd=os.getcwd()
        try:
            os.chdir(root)
            with patch.dict(os.environ,env),patch.object(subprocess,'check_output',return_value=''),patch.object(subprocess,'run',side_effect=lambda command,**kwargs: calls.append((command,kwargs['env'])) or SimpleNamespace(returncode=0)),contextlib.redirect_stdout(output):
                try:runpy.run_path(str(runner),run_name='__main__')
                except SystemExit as error:
                    assert not success,(selection,error)
                    if expected:assert expected in str(error)
                else:assert success,selection
        finally:os.chdir(cwd)
        if not success:assert not calls,selection
        else:
            assert calls,selection
            assert 'Full required verification was not run.' in output.getvalue()
            assert 'All required' not in output.getvalue()
            if browser:
                assert calls[0][1]['VW_UI_DEPS']==str(deps)
                assert calls[0][1]['CERTUTIL']==str(cert)
        print(json.dumps({'selection':selection,'passed':True,'commands':len(calls),'caller_paths_honored':browser}))
    for selection in ['', ' ', 'unknown', 'formatting,unknown', ',formatting', 'formatting,']:
        check(selection,False,'known check names')
    check('formatting',True) # No browser dependencies needed for a non-browser selection.
    check('browser',False,'Browser dependencies unavailable')
    check('browser',True,browser=True)
print('9 isolated runner guard cases passed; verification subprocesses were mocked.')

# Exercise the real mutation runner with isolated source files and fake test processes.
mutation_runner=Path('docs/implementation/1-9-evidence/semantic-mutation-runner.py').resolve()
with tempfile.TemporaryDirectory(prefix='story19-mutant-guards-') as directory:
    root=Path(directory)
    (root/'src/adapters').mkdir(parents=True)
    (root/'src/access').mkdir(parents=True)
    (root/'src/adapters/loopback_ui.rs').write_text('function visibleText(value){return String(value);}')
    source=root/'src/access/history.rs'
    original='uid: record.owner_uid,'
    source.write_text(original)
    def mutation_check(selection, valid, interruption=False):
        calls=[];output=io.StringIO()
        def process(command, **kwargs):
            calls.append(command)
            if len(calls)==1:
                assert source.read_text()==original
                return SimpleNamespace(returncode=0)
            assert source.read_text()=='uid: record.owner_uid + 1,'
            if interruption: raise RuntimeError('isolated mutation process interruption')
            kwargs['stdout'].write('test result: FAILED\n')
            return SimpleNamespace(returncode=101)
        cwd=os.getcwd()
        try:
            os.chdir(root)
            with patch.dict(os.environ,{'STORY19_MUTANT_FILTER':selection,'STORY19_MUTATION_PHASE':'guard'}),patch.object(subprocess,'run',side_effect=process),contextlib.redirect_stdout(output):
                try:runpy.run_path(str(mutation_runner),run_name='__main__')
                except SystemExit as error:
                    assert not valid
                    assert 'known mutant names' in str(error)
                except RuntimeError:
                    assert interruption
                else:
                    assert valid and not interruption
        finally:os.chdir(cwd)
        assert len(calls)==(2 if valid else 0)
        assert source.read_text()==original
        print(json.dumps({'mutant_selection':selection,'passed':True,'commands':len(calls),'restored_after_interruption':interruption}))
    for selection in ['', ' ', 'unknown', 'requester-attribution,unknown', ',requester-attribution', 'requester-attribution,']:
        mutation_check(selection,False)
    mutation_check('requester-attribution',True)
    mutation_check('requester-attribution',True,interruption=True)
print('8 isolated mutation selector/restoration cases passed; test subprocesses were mocked.')
