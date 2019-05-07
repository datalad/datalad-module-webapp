from flask import (
    abort,
    jsonify,
)
from flask_restful import (
    reqparse,
)
import os
import os.path as op
from fnmatch import fnmatch

from datalad.api import (
    get,
    remove,
)

from datalad_webapp import verify_authentication
from datalad_webapp.resource import WebAppResource
from datalad.support import json_py
from datalad.support.constraints import (
    EnsureBool,
    EnsureChoice,
)
import logging
lgr = logging.getLogger('datalad.webapp.resources.file')


class FileResource(WebAppResource):
    # any arg is treated as a relative path
    _urlarg_spec = '<path:path>'

    def __init__(self, *args, **kwargs):
        super(FileResource, self).__init__(*args, **kwargs)
        # setup parser
        bool_type = EnsureBool()
        json_type = EnsureChoice('yes', 'no', 'stream')
        self.rp = reqparse.RequestParser()
        self.rp.add_argument(
            'path', type=str,
            help="""path to file. If none is given, or the path contains a
            wildcard character '*', a list of (matching) files in the
            dataset is returned.""",
            location=['args', 'json', 'form'])
        self.rp.add_argument(
            'json', type=json_type,
            default='no',
            help='%s. {error_msg}' % repr(json_type),
            location=['args', 'json', 'form'])
        self.rp.add_argument(
            'verify_availability', type=bool_type,
            default='yes',
            help='%s. {error_msg}' % repr(bool_type),
            location=['args', 'json', 'form'])
        self.rp.add_argument(
            'content',
            help='file content',
            location=['form', 'json'])
        self.rp.add_argument(
            'togit', type=bool_type,
            help="""flag whether to add files to git, instead of making a
            decision based on the dataset configuration. %s. {error_msg}"""
            % repr(bool_type),
            location=['json', 'form'])
        # TODO message argument for commits

    def _validate_file_path(self, path, fail_nonexistent=True):
        file_abspath = op.join(self.ds.path, path)
        if op.relpath(file_abspath, self.ds.path).startswith(op.pardir):
            # XXX not sure if this can actually happen
            # something funky is going on -> forbidden
            abort(403)
        if fail_nonexistent and not op.exists(file_abspath):
            abort(404)
        if op.exists(file_abspath) and op.isdir(file_abspath):
            # -> rejected due to semantic error: dir != file
            abort(422)
        return file_abspath

    @verify_authentication
    def get(self, path=None):
        args = self.rp.parse_args()
        # either use value from routing, or from request
        path = path or args.path
        if path is None or '*' in path:
            path = path if path else '*'
            # no path, give list of available files
            return jsonify({
                'files': [f for f in self.ds.repo.get_indexed_files()
                          if fnmatch(f, path)],
            })

        file_abspath = self._validate_file_path(path)
        if not self.read_only:
            # in read only mode we cannot do this, as it might cause
            # more datasets to be install etc...
            self.ds.get(file_abspath)
        # TODO proper error reporting when loading/decoding fails
        if args.json == 'stream':
            content = list(json_py.load_stream(file_abspath))
        elif args.json == 'yes':
            content = json_py.load(file_abspath)
        else:
            content = open(file_abspath, 'r').read()

        return jsonify({
            'path': path,
            'content': content,
        })

    # TODO support compression
    @verify_authentication
    def put(self, path=None):
        if self.read_only:
            abort(403)
        args = self.rp.parse_args()
        path = path or args.path
        if path is None or args.content is None:
            # BadRequest
            abort(400)
        file_abspath = self._validate_file_path(
            path, fail_nonexistent=False)
        # TODO handle failure without crashing
        if op.exists(file_abspath):
            self.ds.repo.remove(file_abspath)
        # TODO git checkout of that removed files, when
        # below fails
        # TODO support file uploads
        dirname = op.dirname(file_abspath)
        if not op.exists(dirname):
            os.makedirs(dirname)
        if args.json == 'stream':
            json_py.dump2stream(
                json_py.loads(args.content), file_abspath)
        elif args.json == 'yes':
            json_py.dump(
                json_py.loads(args.content), file_abspath)
        else:
            open(file_abspath, 'w').write(args.content)
        self.ds.rev_save(
            file_abspath,
            to_git=args.togit,
            #message="",
        )

    @verify_authentication
    def delete(self, path=None):
        if self.read_only:
            abort(403)
        args = self.rp.parse_args()
        # either use value from routing, or from request
        path = path or args.path
        if path is None:
            # BadRequest
            abort(400)
        file_abspath = self._validate_file_path(path)

        return self.ds.remove(
            file_abspath,
            check=args.verify_availability,
        )
