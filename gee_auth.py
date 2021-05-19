# -*- coding: utf-8 -*-
# ***************************************************************************
# *                                                                         *
# *   This program is free software; you can redistribute it and/or modify  *
# *   it under the terms of the GNU General Public License as published by  *
# *   the Free Software Foundation; either version 2 of the License, or     *
# *   (at your option) any later version.                                   *
# *   It based on Google Earth Engine plugin by Gennadii Donchyts.          *
# *                                                                         *
# ***************************************************************************

from qgis.PyQt.QtWidgets import *
from qgis.PyQt import uic
from qgis.PyQt.QtWidgets import QAction
from qgis.PyQt.QtGui import QIcon

from qgis.core import Qgis

import base64
import errno
import hashlib
import json
import os
import webbrowser
import six
from six.moves.urllib import parse
from six.moves.urllib import request
from six.moves.urllib.error import HTTPError

Ui_authDialogBase = uic.loadUiType(os.path.join(os.path.dirname(__file__), 'gee_auth.ui'))[0]
CLIENT_ID = ('517222506229-vsmmajv00ul0bs7p89v5m89qs8eb9359.'
             'apps.googleusercontent.com')
CLIENT_SECRET = 'RUP0RZ6e0pPhDzsqIJ7KlNd1'
SCOPES = [
    'https://www.googleapis.com/auth/earthengine',
    'https://www.googleapis.com/auth/devstorage.full_control'
]
REDIRECT_URI = 'urn:ietf:wg:oauth:2.0:oob'
TOKEN_URI = 'https://accounts.google.com/o/oauth2/token'

class authDialog (QDialog, Ui_authDialogBase):
  def __init__(self, parent):
    super().__init__()
    self.iface = parent
    self.setupUi(self)

class GEE_auth_Plugin():
  def __init__(self, iface):
    self.iface = iface


  def initGui(self):
    icon = QIcon(os.path.join(os.path.dirname(__file__), "gee_auth.png"))
    self.authAction = QAction(icon, 'Authenticate GEE', self.iface.mainWindow())
    self.iface.addPluginToMenu('Google Earth Engine Plugin', self.authAction)
    self.authAction.triggered.connect(self.authRun)

  def unload(self):
    self.iface.removePluginMenu('Google Earth Engine Plugin', self.authAction)
    self.iface.unregisterMainWindowAction(self.authAction)

  def authRun(self):
    code_verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=')
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier).digest()).rstrip(b'=')
    auth_url = self.get_authorization_url(code_challenge)
    text = 'To authorize access needed by Earth Engine, you will be redirected to Google Earth engine site. \n Follow the instructions in opened web browser.\nThe authorization workflow will generate a code, which you should paste in the box below.'

    dlg = authDialog(self.iface)
    dlg.label.setText(text)

    webbrowser.open_new(auth_url)

    dlg.exec_()
    if dlg.result():
      auth_code = dlg.auth_code.toPlainText()

    assert isinstance(auth_code, six.string_types)
    token = self.request_token(auth_code.strip(), code_verifier)
    self.write_token(token)
    self.iface.messageBar().pushMessage("", "Authentication process completed successfully.", level=Qgis.Info, duration=4)

  def get_authorization_url(self, code_challenge):
    """Returns a URL to generate an auth code."""

    return 'https://accounts.google.com/o/oauth2/auth?' + parse.urlencode({
        'client_id': CLIENT_ID,
        'scope': ' '.join(SCOPES),
        'redirect_uri': REDIRECT_URI,
        'response_type': 'code',
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256',
    })

  def request_token(self, auth_code, code_verifier):
    """Uses authorization code to request tokens."""

    request_args = {
        'code': auth_code,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'redirect_uri': REDIRECT_URI,
        'grant_type': 'authorization_code',
        'code_verifier': code_verifier,
    }

    refresh_token = None

    try:
      response = request.urlopen(
          TOKEN_URI,
          parse.urlencode(request_args).encode()).read().decode()
      refresh_token = json.loads(response)['refresh_token']
    except HTTPError as e:
      raise Exception('Problem requesting tokens. Please try again.  %s %s' %
                      (e, e.read()))

    return refresh_token

  def get_credentials_path(self):
    cred_path = os.path.expanduser('~/.config/earthengine/credentials')
    return cred_path


  def write_token(self, refresh_token):
    """Attempts to write the passed token to the given user directory."""

    credentials_path = self.get_credentials_path()
    dirname = os.path.dirname(credentials_path)
    try:
      os.makedirs(dirname)
    except OSError as e:
      if e.errno != errno.EEXIST:
        raise Exception('Error creating directory %s: %s' % (dirname, e))

    file_content = json.dumps({'refresh_token': refresh_token})
    if os.path.exists(credentials_path):
      os.remove(credentials_path)
    with os.fdopen(
        os.open(credentials_path, os.O_WRONLY | os.O_CREAT, 0o600), 'w') as f:
      f.write(file_content)
