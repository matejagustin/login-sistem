#!/usr/bin/env python

from google.appengine.ext.webapp import template
from google.appengine.ext import ndb

import logging
import os.path
import webapp2
from webapp2_extras import auth
from webapp2_extras import sessions
from webapp2_extras.auth import InvalidAuthIdError
from webapp2_extras.auth import InvalidPasswordError
from models import Sporocilo

def user_required(handler):
    def check_login(self, *args, **kwargs):
        auth = self.auth
        if not auth.get_user_by_session():
            self.redirect(self.uri_for('login'), abort=True)
        else:
            return handler(self, *args, **kwargs)
    return check_login

class BaseHandler(webapp2.RequestHandler):

    @webapp2.cached_property
    def auth(self):
        return auth.get_auth()

    @webapp2.cached_property
    def user_info(self):
        return self.auth.get_user_by_session()

    @webapp2.cached_property
    def user(self):
        u = self.user_info
        return self.user_model.get_by_id(u['user_id']) if u else None

    @webapp2.cached_property
    def user_model(self):
        return self.auth.store.user_model

    @webapp2.cached_property
    def session(self):
        return self.session_store.get_session(backend="datastore")

    def render_template(self, view_filename, params=None):
        if not params:
            params = {}
        user = self.user_info
        params['user'] = user
        path = os.path.join(os.path.dirname(__file__), 'views', view_filename)
        self.response.out.write(template.render(path, params))

    def display_message(self, message):
        params = {'message': message}
        self.render_template('message.html', params)

    def dispatch(self):
        self.session_store = sessions.get_store(request=self.request)

        try:
            webapp2.RequestHandler.dispatch(self)
        finally:
            self.session_store.save_sessions(self.response)

class MainHandler(BaseHandler):
    def get(self):
        self.render_template('home.html')

class SignupHandler(BaseHandler):
    def get(self):
        self.render_template('signup.html')

    def post(self):
        user_name = self.request.get('username')
        email = self.request.get('email')
        name = self.request.get('name')
        password = self.request.get('password')
        last_name = self.request.get('lastname')

        unique_properties = ['email_address']
        user_data = self.user_model.create_user(user_name,
            unique_properties,
            email_address=email, name=name, password_raw=password,
            last_name=last_name, verified=False)

        if not user_data[0]: #user_data is a tuple
            self.display_message('Unable to create user for email %s because of \
                duplicate keys %s' % (user_name, user_data[1]))
            return
    
        user = user_data[1]
        user_id = user.get_id()

        token = self.user_model.create_signup_token(user_id)

        verification_url = self.uri_for('verification', type='v', user_id=user_id,
            signup_token=token, _full=True)

        self.redirect_to("login", url=verification_url)

class VerificationHandler(BaseHandler):
    def get(self, *args, **kwargs):
        user = None
        user_id = kwargs['user_id']
        signup_token = kwargs['signup_token']
        verification_type = kwargs['type']

        user, ts = self.user_model.get_by_auth_token(int(user_id), signup_token,
            'signup')

        if not user:
            logging.info('Could not find any user with id "%s" signup token "%s"',
                user_id, signup_token)
            self.abort(404)

        self.auth.set_session(self.auth.store.user_to_dict(user), remember=True)

        if verification_type == 'v':
            self.user_model.delete_signup_token(user.get_id(), signup_token)

            if not user.verified:
                user.verified = True
                user.put()

            self.display_message('User email address has been verified.')
            return

        elif verification_type == 'p':
            params = {'user': user,'token': signup_token}
            self.render_template('resetpassword.html', params)
        else:
            logging.info('verification type not supported')
            self.abort(404)

class SetPasswordHandler(BaseHandler):

    @user_required
    def post(self):
        password = self.request.get('password')
        old_token = self.request.get('t')

        if not password or password != self.request.get('confirm_password'):
            self.display_message('passwords do not match')
            return

        user = self.user
        user.set_password(password)
        user.put()

        self.user_model.delete_signup_token(user.get_id(), old_token)
    
        self.display_message('Password updated')

class LoginHandler(BaseHandler):
    def get(self):
        self._serve_page()

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        try:
            u = self.auth.get_user_by_password(username, password, remember=True,
                save_session=True)
            self.redirect(self.uri_for('chat'))
        except (InvalidAuthIdError, InvalidPasswordError) as e:
            logging.info('Login failed for user %s because of %s', username, type(e))
            self._serve_page(True)

    def _serve_page(self, failed=False):
        username = self.request.get('username')
        params = {'username': username,'failed': failed}

        self.render_template('login.html', params)



class LogoutHandler(BaseHandler):
    def get(self):
        self.auth.unset_session()
        self.redirect(self.uri_for('home'))

class AuthenticatedHandler(BaseHandler):
    @user_required
    def get(self):
        self.render_template('authenticated.html')

config = {
    'webapp2_extras.auth': {
        'user_model': 'models.User',
        'user_attributes': ['name']
    },
    'webapp2_extras.sessions': {
    'secret_key': 'YOUR_SECRET_KEY'
    }
}


class ChatHandler(BaseHandler):
    def get(self):
        msg = Sporocilo.query().fetch()
        ime = Sporocilo.query().order(-Sporocilo.name).fetch()
        params = {"msg": msg,"ime":ime}
        self.render_template("chat.html",params=params)

    def post(self):
        msg = self.request.get("msg")


        x = self.user
        name = x.auth_ids[0]

        msg = Sporocilo(msg=msg,name=name)
        msg.put()

        self.redirect_to("chat")

app = webapp2.WSGIApplication([
    webapp2.Route('/', MainHandler, name='home'),
    webapp2.Route('/signup', SignupHandler, name='signup'),
    webapp2.Route('/<type:v|p>/<user_id:\d+>-<signup_token:.+>',
      handler=VerificationHandler, name='verification'),
    webapp2.Route('/password', SetPasswordHandler),
    webapp2.Route('/login', LoginHandler, name='login'),
    webapp2.Route('/logout', LogoutHandler, name='logout'),
    webapp2.Route('/authenticated', AuthenticatedHandler, name='authenticated'),
    webapp2.Route('/chat',ChatHandler, name='chat'),
], debug=True, config=config)

logging.getLogger().setLevel(logging.DEBUG)
