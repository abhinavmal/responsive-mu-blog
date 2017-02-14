# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import os
import webapp2
import cgi
import jinja2
import re
import time
import datetime
import hashlib
import hmac

# To make salt
import random
import string

# JSON
import json

# Time zone
import pytz

# DB : ndb
from google.appengine.ext import ndb

SECRET = "iamsosecret"

"""Jinja environment initialization
   Jinja will look for templates in template_dir
"""
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


def escape_html(str):
    return cgi.escape(str, quote=True)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]{4,100}@[\S]+.[\S]+$")


def valid_username(username):
    return USER_RE.match(username)


def valid_password(password):
    return PASS_RE.match(password)


def valid_email(email):
    if not email:
        return True
    return EMAIL_RE.match(email)


# Cookie Security
def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()


def make_secure_val(s):
    return s + "|" + hash_str(s)


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val
# End of stuff for cookie security


# user stuff
def make_salt(length=5):
    return ''.join(random.SystemRandom()
                   .choice(string.ascii_uppercase + string.digits)
                   for _ in range(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)
# End of user stuff


# Entities
class User(ndb.Model):
    """The User class describes the use that logs in
    to the blog.
    """
    username = ndb.StringProperty(required=True)
    pw_hash = ndb.StringProperty(required=True)
    email = ndb.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid)

    @classmethod
    def by_name(cls, name):
        u = User.query(User.username == name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(
                    name=name,
                    pw_hash=pw_hash,
                    email=email
                    )

    @classmethod
    def return_valid_user_obj(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


class Post(ndb.Model):
    """A set of attributes to describe the post
    """
    title = ndb.StringProperty(required=True)
    body = ndb.TextProperty(required=True)
    created = ndb.DateTimeProperty(auto_now=True)
    author = ndb.StructuredProperty(User)
    num_likes = ndb.IntegerProperty()
    num_dislikes = ndb.IntegerProperty()
    likes = ndb.StringProperty(repeated=True)
    dislikes = ndb.StringProperty(repeated=True)

    def get_date(self, format='%B %d, %Y'):
        # return self.created.date().strftime(format)
        unaware_est = datetime.datetime.strptime(str(self.created),
                                                 "%Y-%m-%d %H:%M:%S.%f")
        # timeUTC = self.created.time().strftime(format)
        # http://stackoverflow.com/questions/18176148/converting-an-un-aware-timestamp-into-an-aware-timestamp-for-utc-conversion
        timezone_local = pytz.timezone("America/Chicago")
        utc = pytz.utc
        time_local = utc.localize(unaware_est).astimezone(timezone_local)
        return time_local.strftime(format)

    def get_time(self, format='%I:%M %p'):
        # Manipulation to bring it to Central Time US
        unaware_est = datetime.datetime.strptime(str(self.created),
                                                 "%Y-%m-%d %H:%M:%S.%f")
        # timeUTC = self.created.time().strftime(format)
        # http://stackoverflow.com/questions/18176148/converting-an-un-aware-timestamp-into-an-aware-timestamp-for-utc-conversion
        timezone_local = pytz.timezone("America/Chicago")
        utc = pytz.utc
        time_local = utc.localize(unaware_est).astimezone(timezone_local)
        return time_local.strftime(format)


class Comment(ndb.Model):
    """A set of attributes to describe the comments on posts
    """
    author = ndb.StructuredProperty(User)
    content = ndb.TextProperty()
    created = ndb.DateTimeProperty(auto_now=True)
    for_post = ndb.StringProperty()

    def get_date(self, format='%B %d, %Y'):
        # return self.created.date().strftime(format)
        unaware_est = datetime.datetime.strptime(str(self.created),
                                                 "%Y-%m-%d %H:%M:%S.%f")
        # timeUTC = self.created.time().strftime(format)
        # http://stackoverflow.com/questions/18176148/converting-an-un-aware-timestamp-into-an-aware-timestamp-for-utc-conversion
        timezone_local = pytz.timezone("America/Chicago")
        utc = pytz.utc
        time_local = utc.localize(unaware_est).astimezone(timezone_local)
        return time_local.strftime(format)

    def get_time(self, format='%I:%M %p'):
        # Manipulation to bring it to Central Time US
        unaware_est = datetime.datetime.strptime(str(self.created),
                                                 "%Y-%m-%d %H:%M:%S.%f")
        # timeUTC = self.created.time().strftime(format)
        # http://stackoverflow.com/questions/18176148/converting-an-un-aware-timestamp-into-an-aware-timestamp-for-utc-conversion
        timezone_local = pytz.timezone("America/Chicago")
        utc = pytz.utc
        time_local = utc.localize(unaware_est).astimezone(timezone_local)
        return time_local.strftime(format)


# standard handler for writing output to a template
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key.id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie',
                                         'user_id=; Path=/')

    def check_user_cookie(self, cookie_name):
        current_user_cookie = self.read_secure_cookie(cookie_name)
        if current_user_cookie:
            user = User.get_by_id(long(current_user_cookie))
            return user
        else:
            return None


class MainPage(Handler):
    def get(self):
        posts = Post.query().order(-Post.created).fetch()
        user = self.check_user_cookie("user_id")
        params_home = dict(posts=posts)
        params_home["body"] = ""
        params_home["error"] = ""
        params_home["user"] = user
        self.render("home.html", **params_home)


class CreatePost(Handler):
    def get(self):
        user = self.check_user_cookie("user_id")
        if not user:
            self.redirect("/login")
            return
        else:
            self.render("create_post.html", user=user)

    def post(self):
        user = self.check_user_cookie("user_id")
        if not user:
            self.redirect("/login")
            return
        title = self.request.get("subject")
        body = self.request.get("content")
        if title and body:
            post = Post(title=title, body=body, author=user,
                        num_likes=0, num_dislikes=0)
            post_key = post.put()
            # Time.sleep() for eventual consistency of the database
            time.sleep(0.1)
            self.redirect("/singlepost/"+str(post_key.id()))
            return
        else:
            error = "We need both a title and some body!"
            self.render("create_post.html", error=error, title=title,
                        body=body, user=user)


class SinglePost(Handler):
    def get(self, post_id):
        user = self.check_user_cookie("user_id")
        post = Post.get_by_id(long(post_id))
        post_comments = Comment.query(Comment.for_post == str(post_id)) \
                               .order(-Comment.created) \
                               .fetch()
        author_is_user = False
        if user and post.author.username == user.username:
            author_is_user = True
        self.render("single_post.html", post=post, post_id=str(post_id),
                    user=user, comments=post_comments,
                    author_is_user=author_is_user)

    def post(self, post_id):
        user = self.check_user_cookie("user_id")
        if not user:
            self.redirect("/login")
            return
        comment = self.request.get("comment_input")
        post = Post.get_by_id(long(post_id))
        post_comments = Comment.query(Comment.for_post == str(post_id)) \
                               .order(-Comment.created) \
                               .fetch()
        author_is_user = False
        if post.author.username == user.username:
            author_is_user = True
        if not comment:
            error_comment = "We need some text in comment!"
            self.render("single_post.html", post=post, post_id=str(post_id),
                        user=user, comments=post_comments,
                        author_is_user=author_is_user,
                        error_comment=error_comment)
            return
        new_comment = Comment(author=user, content=comment,
                              for_post=str(post_id))
        comm_key = new_comment.put()
        # Time.sleep() for eventual consistency of the database
        time.sleep(0.5)
        # I redirected so that if the user refreshes, it calls the GET function
        # and not POST function. There is a return after redirect because
        # it may not stop execution by itself
        self.redirect("/singlepost/" + str(post_id))
        return


class SignupHandler(Handler):
    def validate_input(self, username, password, verify_pass, email):
        username_error = ""
        password_error = ""
        password_error_start = ""
        email_error = ""
        have_error = False
        params = dict()
        if not password or not valid_password(password):
            params["password_error_start"] = "That password was not correct."
            have_error = True
        if password != verify_pass:
            params["password_error"] = "Your passwords didn't match."
            have_error = True
        if (' ' in username) or not username or \
           not valid_username(username):
            params["username_error"] = "Not valid username. Valid one is " + \
                                       "min 3 & max 20 chars, where chars " + \
                                       "can be letters, alphabets, '_' or '-'"
            have_error = True
        if email and ('@' not in email) and ('.' not in email) or \
           not valid_email(email):
            params["email_error"] = "That's not a valid email."
            have_error = True
        if have_error:
            return params
        else:
            return None

    def get(self):
        self.render("signup.html", username_error="", password_error_start="",
                    password_error="", email_error="")

    def post(self):
        username = self.request.get("username").strip()
        password = self.request.get("password")
        verify_pass = self.request.get("verify")
        email = self.request.get("email").strip()
        error_params = self.validate_input(username, password,
                                           verify_pass, email)
        #  Check is username exists
        username_exists_error = None
        existing_user = User.query(User.username == username).fetch(1)
        if existing_user:
            error_params["username_exists_error"] = "This username \
                                                     already exists."
        if username_exists_error or error_params:
            self.render("signup.html", **error_params)
        else:
            user_obj = User(username=username,
                            pw_hash=make_pw_hash(username, password),
                            email=str(email))
            user_key = user_obj.put()
            self.set_secure_cookie("user_id", str(user_key.id()))
            self.redirect("./registered")
            return


class ValidPage(Handler):
    def get(self):
        user = self.check_user_cookie("user_id")
        if not user:
            self.redirect("/login")
            return
        self.render("registered.html", user=user)


class LoginHandler(Handler):
    def get(self):
        self.render("login.html", username_error="", password_error="")

    def post(self):
        # Strip trailing spaces, if they exist
        username = self.request.get("username").strip()
        password = self.request.get("password")
        username_error = ""
        password_error = ""
        if not valid_username(username):
            username_error = "That is not valid username"
        if not valid_password(password):
            password_error = "That is not valid password"
        if username_error or password_error:
            self.render("login.html", username_error=username_error,
                        password_error=password_error, username=username)
        else:
            # check for valid username in database
            u = User.return_valid_user_obj(username, password)
            if u:
                self.login(u)
                self.redirect("./registered")
                return
            username_error = "Username/Password Invalid!"
            password_error = "Username/Password Invalid!"
            self.render("login.html", username_error=username_error,
                        password_error=password_error, username=username)


class LogoutHandler(Handler):
    def get(self):
        # Delete Cookie
        self.logout()
        self.redirect("./")
        return


# Function to handle the AJAX request for liking or disliking a post
class PostStatsUpdate(Handler):
    def post(self):
        user = self.check_user_cookie("user_id")
        if not user:
            self.redirect("/login")
            return
        post_id = self.request.get("post_id")
        update_type = self.request.get("type")
        post = Post.get_by_id(long(post_id))
        post_likes_dislikes_users = post.likes + post.dislikes
        if update_type == "like" and user.username in post.dislikes:
            data = {"error": "You already " +
                             "disliked this one! Can't like it now!"}
            self.response.out.write(json.dumps(data))
            return
        if update_type == "dislike" and user.username in post.likes:
            data = {"error": "You already " +
                             "liked this one! Can't dislike it now!"}
            self.response.out.write(json.dumps(data))
            return
        if update_type == "like" and user.username not in post.likes:
            post.num_likes += 1
            post.likes.append(user.username)
            post.put()
            time.sleep(0.5)
            data = {"count": post.num_likes}
            self.response.out.write(json.dumps(data))
        elif update_type == "dislike" and user.username not in post.dislikes:
            post.num_dislikes += 1
            post.dislikes.append(user.username)
            post.put()
            time.sleep(0.5)
            data = {"count": post.num_dislikes}
            self.response.out.write(json.dumps(data))
        else:
            data = {"error": "You already " + update_type +
                             "d this one!"}
            self.response.out.write(json.dumps(data))
        return


class EditPost(Handler):
    def get(self, post_id):
        user = self.check_user_cookie("user_id")
        if not user:
            self.redirect("/login")
            return
        post = Post.get_by_id(long(post_id))
        self.render("edit_post.html", user=user, post=post,
                    post_id=str(post_id))

    def post(self, post_id):
        title = self.request.get("subject").strip()
        body = self.request.get("content").strip()
        user = self.check_user_cookie("user_id")
        if not user:
            self.redirect("/login")
            return
        if title and body:
            post = Post.get_by_id(long(post_id))
            post.title = title
            post.body = body
            p_key = post.put()
            # Time.sleep() for eventual consistency of the database
            time.sleep(0.1)
            self.redirect("/singlepost/"+str(p_key.id()))
            return
        else:
            error = "We need both a title and some body!"
            self.render("create_post.html", error=error, post=post,
                        user=user)


class DeletePost(Handler):
    def get(self, post_id):
        user = self.check_user_cookie("user_id")
        if not user:
            self.redirect("/login")
            return
        post = Post.get_by_id(long(post_id))
        if post:
            del_title = post.title
            del_body = post.body
            del_likes = post.num_likes
            del_dislikes = post.num_dislikes
            del_author = post.author
            del_date = post.get_date()
            del_time = post.get_time()
            # Delete all comments associated with the post
            comments = Comment.query(Comment.for_post == str(post_id))
            for comment in comments:
                comment.key.delete()
            post.key.delete()
            self.render("delete_post.html", user=user, title=del_title,
                        body=del_body, author=del_author,
                        post_id=str(post_id), date=del_date, time=del_time)
        else:
            self.redirect("/")
            return


class EditComment(Handler):
    def get(self, post_id, comment_id):
        user = self.check_user_cookie("user_id")
        if not user:
            self.redirect("/login")
            return
        post = Post.get_by_id(long(post_id))
        cur_comment = Comment.get_by_id(long(comment_id))
        post_comments = Comment.query(Comment.for_post == str(post_id)) \
                               .order(-Comment.created) \
                               .fetch()
        self.render("edit_comment.html", user=user, post=post,
                    comment_id=comment_id, current_comment=cur_comment,
                    comments=post_comments, post_id=post_id)

    def post(self, post_id, comment_id):
        title = self.request.get("subject")
        body = self.request.get("content")
        user = self.check_user_cookie("user_id")
        if not user:
            self.redirect("/login")
            return
        comment = self.request.get("comment_input")
        post = Post.get_by_id(long(post_id))
        if comment:
            c = Comment.get_by_id(long(comment_id))
            c.content = comment
            c.put()
            # Time.sleep() for eventual consistency of the database
            time.sleep(0.1)
            self.redirect("/singlepost/"+str(post_id))
            # self.redirect("/singlepost/" + str(post_id))
            return
        else:
            error = "We need some comment!"
            self.render("edit_comment.html", error_comment=error,
                        user=user, post=post, comment_id=comment_id,
                        current_comment=comment, post_id=post_id)


class DeleteComment(Handler):
    def get(self, post_id, comment_id):
        user = self.check_user_cookie("user_id")
        if not user:
            self.redirect("/login")
            return
        post = Post.get_by_id(long(post_id))
        del_comment = Comment.get_by_id(long(comment_id))
        if del_comment:
            del_title = post.title
            del_body = post.body
            del_likes = post.num_likes
            del_dislikes = post.num_dislikes
            del_author = post.author
            # Delete the specific comment associated with the post
            del_comment.key.delete()
            self.render("delete_comment.html", del_comment=del_comment,
                        user=user, title=post.title, body=post.body,
                        author=post.author, post_id=str(post_id))
        else:
            self.redirect("/")
            return


app = webapp2.WSGIApplication([
                              ('/newpost', CreatePost),
                              ('/signup', SignupHandler),
                              ('/registered', ValidPage),
                              ('/login', LoginHandler),
                              ('/logout', LogoutHandler),
                              ('/post-stats-update/', PostStatsUpdate),
                              (r'/singlepost/(\d+)', SinglePost),
                              (r'/edit-post/(\d+)', EditPost),
                              (r'/delete-post/(\d+)', DeletePost),
                              (r'/edit-comment/(\d+)/(\d+)', EditComment),
                              (r'/delete-comment/(\d+)/(\d+)', DeleteComment),
                              ('/', MainPage)
                              ], debug=True)
