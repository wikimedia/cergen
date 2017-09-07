import pytest
import tempfile

from cergen.command import run_command

from fixtures import *

def test_run_command():
    assert run_command('echo test'), \
        'Should return True'
    assert not run_command('cat _non-_-existent_'), \
        'Should return False'

    assert not run_command('echo test', creates='_non-_-existent_'), \
        'Should check file existence and return False'

    # This doesn't test that the command actually creates f.name, but it does
    # check that run_command verifies that the file exists.
    with tempfile.NamedTemporaryFile() as f:
        f.write(b'cergen test')
        assert run_command('test -f {}'.format(f.name), creates=f.name), \
            'Should check file existence'

