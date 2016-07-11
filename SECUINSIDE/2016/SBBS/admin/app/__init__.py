# -*- coding:utf-8 -*-
import os

from flask import Flask, abort, request, render_template_string

from config import config
from utils.validator import validate_request_url

template = """
{%% extends "base.html" %%}
{%% block content_body %%}
    {{ title | safe }}
    <p>%s</p>
{%% endblock %%}
"""

title_404 = "<h1>404 Not Found</h1>"
title_405 = "<h1>405 Method Not Allowed</h1>"
FLAG = "FLAG{**********************************}"  # Can you read it?


def create_app():
    project_root = getattr(config, 'PROJECT_ROOT')
    template_folder = os.path.join(project_root, 'admin/templates')
    static_folder = os.path.join(project_root, 'admin/static')

    app = Flask(__name__, template_folder=template_folder, static_folder=static_folder)
    app.config.from_object(config)

    allowed_hosts = getattr(config, 'ALLOWED_HOSTS')

    @app.before_request
    def before_request():
        if request.remote_addr not in allowed_hosts:
            return abort(403)

    def from_string(source, globals=None, template_class=None):
        globals = app.jinja_env.make_globals(globals)
        cls = template_class or app.jinja_env.template_class

        if not validate_request_url(request.url):
            return cls.from_code(
                app.jinja_env,
                app.jinja_env.compile(u"Bad Request (Request was filtered)"),
                globals,
                None,
            )

        return cls.from_code(app.jinja_env, app.jinja_env.compile(source), globals, None)

    @app.errorhandler(404)
    def not_found(e=None):
        message = "%s was not found on the server." % request.url
        template_string = template % message
        return render_template_string(template_string, title=title_404), 404

    @app.errorhandler(405)
    def method_not_allowed(e=None):
        message = "%s is not allowed for %s" % (request.method, request.path)
        template_string = template % message
        return render_template_string(template_string, title=title_405), 405

    app.jinja_env.from_string = from_string
    app.jinja_env.filters.update(id=id)

    __import__('admin.app.controllers', 'controllers', fromlist=['controllers'])
    blueprint_module = __import__('admin.app.blueprint', 'blueprint', fromlist=['blueprint'])

    blueprint = getattr(blueprint_module, 'blueprint')
    app.register_blueprint(blueprint)
    
    return app
