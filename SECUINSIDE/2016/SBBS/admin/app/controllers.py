# -*- coding:utf-8 -*-
from flask import abort, render_template, request

from models.post import Post, PostStatus
from .blueprint import blueprint


@blueprint.get('/posts')
def post_list_view():
    page = request.args.get('page', default=1, type=int)
    per_page = 30
    pagination = Post.query\
        .filter(Post.status == PostStatus.sent.value)\
        .order_by(Post.id.desc())\
        .paginate(page, per_page)
    return render_template("list.html", pagination=pagination)


@blueprint.get('/posts/<int:post_id>')
def post_detail_view(post_id):
    post = Post.get(post_id)
    if post is None:
        return abort(404)
    return render_template("post.html", post=post)
