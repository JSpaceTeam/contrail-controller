"""
Generate Elastic Search Mapping
"""

import errno
import json
import optparse
import os

from pyang import plugin


def pyang_plugin_init():
    plugin.register_plugin(ElasticSearchMappingPlugin())


class ElasticSearchMappingPlugin(plugin.PyangPlugin):
    def add_output_format(self, fmts):
        self.multiple_modules = True
        fmts['gesm'] = self

    def add_opts(self, optparser):
        optlist = [
            optparse.make_option(
                '--gesm-output',
                dest='directory',
                help='Generate output to DIRECTORY.')
        ]
        g = optparser.add_option_group('GESM output specific options')
        g.add_options(optlist)

    def setup_ctx(self, ctx):
        if ctx.opts.format == 'gesm':
            if not ctx.opts.directory:
                print '''Option --gesm-output not set, defaulting to "gen".'''
                ctx.opts.directory = 'gen'

    def setup_fmt(self, ctx):
        ctx.implicit_errors = False

    def emit(self, ctx, modules, fd):
        mapping(ctx, modules)


def mapping(ctx, modules):
    for module in modules:
        if module.keyword == 'module':
            mapping = {}
            module_node = mapping[module.arg] = {}
            module_node['settings'] = {"index": {"analysis": {"analyzer": {"default": {"type": "simple"}}}}}
            mappings_node = module_node['mappings'] = {}

            for child in module.i_children:
                kwds = ['list', 'container']
                if child.keyword in kwds:
                    document_type_name = child.arg.replace('-', '_')
                    map_node(child, module, mappings_node, document_type_name)
            file = '%s%s%s.mapping.json' % (ctx.opts.directory, os.sep, module.arg)
            try:
                os.makedirs(ctx.opts.directory, 0o777)
            except OSError as exc:
                if exc.errno == errno.EEXIST:
                    pass  # The directory already exists
                else:
                    raise
            with open(file, 'w') as outfile:
                json.dump(mapping, outfile)
        else:
            bstr = ""
            b = module.search_one('belongs-to')
            if b is not None:
                bstr = " (belongs-to %s)" % b.arg
            print "ERROR: %s.yang is a %s, it belongs to %s.yang" % (module.arg, module.keyword, bstr)


def map_node(s, module, parent_node, document_type_name):
    node_name = s.arg
    _node_name = node_name

    if s.keyword in ('leaf-list', 'leaf'):
        yang_type = get_build_in_type(s).arg
        es_type = get_es_type(yang_type)
        if es_type == 'string':
            parent_node[_node_name] = {'type': 'string', 'index': 'analyzed','fields': {'_raw': {'type': 'string', 'index': 'not_analyzed'},'_%s_suggest' % document_type_name: {'type': 'completion'}}}
        elif es_type == 'double':
            parent_node[_node_name] = {'type': 'double', 'index': 'analyzed','fields': {'_raw': {'type': 'double', 'index': 'not_analyzed'}}}
        elif es_type == 'boolean':
            parent_node[_node_name] = {'type': 'boolean'}
        elif es_type == 'binary':
            parent_node[_node_name] = {'type': 'binary'}
    elif s.keyword in ('choice', 'case') and hasattr(s, 'i_children'):
        children = s.i_children
        for child in children:
            map_node(child, module, parent_node, document_type_name)
    elif hasattr(s, 'i_children'):
        _node_name = node_name.replace('-', '_')
        kwds = ['list', 'container']

        children = s.i_children
        node = parent_node[_node_name] = {}
        node_prop = node['properties'] = {}
        for child in children:
            if child.keyword not in kwds and child.arg != document_type_name:
                map_node(child, module, node_prop, document_type_name)
            else:
                map_node(child, module, parent_node, document_type_name)

def get_build_in_type(stmt):
    """Returns the built in type that stmt is derived from"""
    if stmt.keyword == 'type':
        if stmt.arg == 'union':
            subtype = None
            for substmt in stmt.substmts:
                if subtype is None:
                    subtype = get_build_in_type(substmt)
                else:
                    new_subtype = get_build_in_type(substmt)
                    if subtype.arg != new_subtype.arg:
                        raise RuntimeError(
                            "The base type of member type in union type '%s' are not same " % (stmt.parent.arg))
            return subtype
        else:
            try:
                typedef = stmt.i_typedef
            except AttributeError:
                return stmt
            else:
                if typedef is not None:
                    return get_build_in_type(typedef)
                else:
                    return stmt
    else:
        type_stmt = search_one(stmt, 'type')
        if type_stmt is None:
            return stmt
        if type_stmt.arg == 'leafref':
            ref_node = type_stmt.parent.i_leafref.i_target_node
            return get_build_in_type(ref_node)
        return get_build_in_type(type_stmt)


def search_one(stmt, keyword, arg=None):
    """Utility for calling Statement.search_one, including i_children."""
    res = stmt.search_one(keyword, arg=arg)
    if res is None:
        try:
            res = stmt.search_one(keyword, arg=arg, children=stmt.i_children)
        except AttributeError:
            pass
    return res


def get_es_type(yang_type):
    es_type = yang_type
    if yang_type in ('int8', 'int16', 'int32', 'int64', 'uint8',
                     'uint16', 'uint32', 'uint64'):
        es_type = 'double'
    elif yang_type in ('string', 'enumeration'):
        es_type = 'string'
    elif yang_type == 'boolean':
        es_type = 'boolean'
    elif yang_type == 'binary':
        es_type = 'binary'
    else:
        es_type = 'string'
    return es_type
