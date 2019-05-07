import pytest
import flask
import json
import os.path as op

from datalad.api import (
    create,
    add,
    webapp,
)

from datalad.tests.utils import (
    create_tree,
    assert_result_count,
    ok_file_has_content,
    ok_clean_git,
)

from datalad_webapp.tests.helpers import assert_get_resource_needs_authentication


@pytest.fixture
def client(tmpdir):
    ds = create(tmpdir.strpath)
    res = webapp(
        dataset=ds.path,
        mode='dry-run',
        return_type='item-or-list',
    )
    app = res['app']
    client = app.test_client()

    yield (client, ds)


def test_server_startup(client):
    client, ds = client
    with client as c:
        assert_get_resource_needs_authentication(client, 'file')
        # request list of files
        rv = client.get('/api/v1/file')
        assert {'files': ds.repo.get_indexed_files()} == rv.get_json()


def test_read(client):
    client, ds = client
    with client as c:
        assert c.get('/api/v1/auth').status_code == 200
        existing_files = c.get('/api/v1/file').get_json()['files']

        file_content = '{"three": 3}'
        # resource picks up live changes to the dataset
        create_tree(ds.path, {'subdir': {'dummy': file_content}})
        ds.rev_save()
        current_files = c.get('/api/v1/file').get_json()['files']
        testpath = 'subdir/dummy'
        assert testpath not in existing_files
        assert testpath in current_files

        # simple path filtering
        assert c.get('/api/v1/file/*dummy').get_json()['files'] == [testpath]

        # request file content in various supported ways
        for a, kwa in (
                # plain URL routing
                (('/api/v1/file/subdir/dummy',), {}),
                # URL arg
                (('/api/v1/file?path=subdir%2Fdummy',), {}),
                # form data
                (('/api/v1/file',), {'data': {'path': testpath}}),
                (('/api/v1/file',),
                 {'data': json.dumps(dict(path=testpath)),
                  'content_type': 'application/json'}),
        ):
            rq = c.get(*a, **kwa)
            assert rq.status_code == 200
            assert rq.get_json()['path'] == testpath
            assert rq.get_json()['content'] == file_content

        for j, target in (
                ('no', file_content),
                # JSON decoding
                ('yes', {'three': 3}),
                # JSON stream decoding
                ('stream', [{'three': 3}]),
        ):
            assert c.get(
                '/api/v1/file',
                data=json.dumps(dict(path=testpath, json=j)),
                content_type='application/json',
            ).get_json()['content'] == target


def test_delete(client):
    client, ds = client
    with client as c:
        assert client.delete('/api/v1/file').status_code == 401
        assert c.get('/api/v1/auth').status_code == 200

        # missing path
        assert client.delete('/api/v1/file').status_code == 400

        testpath = 'subdir/dummy'
        file_content = '{"three": 3}'
        # resource picks up live changes to the dataset
        create_tree(ds.path, {'subdir': {'dummy': file_content}})
        ds.rev_save()
        assert testpath in c.get('/api/v1/file').get_json()['files']

        rq = c.delete(
            '/api/v1/file',
            data=json.dumps(dict(
                path=testpath,
                verify_availability=False,
            )),
            content_type='application/json',
        ).get_json()
        if ds.config.obtain('datalad.repo.direct', False):
            # https://github.com/datalad/datalad/issues/2836
            return
        assert_result_count(rq, 1, action='remove',
                            status='ok', path=testpath)
        assert testpath not in c.get('/api/v1/file').get_json()['files']


def test_put(client):
    client, ds = client
    with client as c:
        assert c.get('/api/v1/auth').status_code == 200
    ok_clean_git(ds.path)

    testpath = 'subdir/dummy'
    file_content = '{"three": 3}'
    assert testpath not in c.get('/api/v1/file').get_json()['files']

    count = 0
    for kw, content in (
            ({}, file_content),
            ({'json': 'stream'}, file_content),
            ({'json': 'yes'}, file_content),
    ):
        targetpath = '{}_{}'.format(testpath, count)
        rq = c.put(
            '/api/v1/file/{}'.format(targetpath),
            data=json.dumps(dict(
                content=file_content,
            )),
            content_type='application/json',
        )
        assert rq.status_code == 200
        assert targetpath in c.get('/api/v1/file').get_json()['files']
        ok_file_has_content(
            op.join(ds.path, targetpath),
            content=content)
        count += 1
        ok_clean_git(ds.path)
