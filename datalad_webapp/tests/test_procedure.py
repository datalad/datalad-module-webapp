import os
import pytest
import flask

from datalad.api import create
from datalad.api import webapp


@pytest.fixture
def client(tmpdir):
    ds = create(tmpdir.strpath)

    with open(os.path.join(ds.path, 'dummy_procedure.py'), 'w') as f:
        f.write("import sys; print(\"This is a dummy procedure running in %s\" "
                "% sys.argv[1]")
    ds.add('dummy_procedure.py', to_git=True, save=False)

    ds.config.add(
        'datalad.locations.dataset-procedures',
        '.',
        where='dataset')
    ds.config.add(
        'datalad.procedures.dummy_procedure.call-format',
        'python "{script}" "{ds}" nonsense argument',
        where='dataset'
    )
    ds.config.add(
        'datalad.procedures.dummy_procedure.help',
        "This is a help message",
        where='dataset'
    )
    ds.save(message="dummy procedure added")

    res = webapp(
        dataset=ds.path,
        mode='dry-run',
        return_type='item-or-list',
    )
    app = res['app']

    client = app.test_client()

    yield client, ds


def test_server_startup(client):
    client, ds = client
    with client as c:
        # unauthorized access is prevented
        rv = client.get('/api/v1/procedure')
        assert rv.status_code == 401
        assert 'results' not in rv.get_json()
        # we get no magic authentication
        assert 'api_key' not in flask.session

        # authenticate
        rv = client.get('/api/v1/auth')
        assert rv.status_code == 200

        # request list of files
        rv = client.get('/api/v1/procedure')
        assert rv.status_code == 200

        target_result = {'name': 'dummy_procedure',
                         'path': 'dummy_procedure.py',
                         'format': 'python "{script}" "{ds}" nonsense argument',
                         'help': 'This is a help message',
                         }

        response = rv.get_json()
        results = ds.run_procedure(discover=True)

        assert len(results) == len(response['results'])
        assert [r['name'] for r in response['results']] == \
               [r['procedure_name'] for r in results]
        assert [r['path'] for r in response['results']] == \
               [os.path.relpath(r['path'], ds.path) for r in results]
        assert [r['format'] for r in response['results']] == \
               [r['procedure_callfmt'] for r in results]
        assert [r['help'] for r in response['results']] == \
               [r['procedure_help'] for r in results]

        cmp = [r['path'] == target_result['path'] and
               r['format'] == target_result['format'] and
               r['help'] == target_result['help']
               for r in response['results']
               if r['name'] == target_result['name']]
        assert len(cmp) == 1
        assert cmp[0] is True
