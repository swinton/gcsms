#!/usr/bin/env python
# gcsms.py - Send SMS for free using Google Calendar
# Copyright (C) 2013  Mansour <mansour@oxplot.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""Send SMS for free using Google Calendar."""

from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__author__ = 'Mansour'
__copyright__ = 'Copyright (C) 2013 Mansour'
__credits__ = ['Mansour']
__email__ = 'mansour@oxplot.com'
__license__ = 'GPLv3'
__maintainer__ = 'Mansour'
__version__ = '2.0'

from datetime import datetime
import argparse
import json
import os
import sys
import time

# Version dependent imports

try:
  from ConfigParser \
    import SafeConfigParser, NoSectionError, NoOptionError
except ImportError:
  from configparser \
    import SafeConfigParser, NoSectionError, NoOptionError

try:
  from urllib2 import urlopen, Request as _Request, HTTPError
  from urllib import urlencode
except ImportError:
  from urllib.parse import urlencode
  from urllib.request import urlopen, Request as _Request
  from urllib.error import HTTPError

try:
  unicode = unicode
except NameError:
  unicode = str

_GLOBAL = 'global'
_PROGNAME = 'gcsms'
_MLNAME_PREFIX = _PROGNAME + ':'

_BASE_URL = 'https://www.googleapis.com/calendar/v3'
_DEV_CODE_ENDPT = 'https://accounts.google.com/o/oauth2/device/code'
_GRANT_TYPE = 'http://oauth.net/grant_type/device/1.0'
_SCOPE = 'https://www.googleapis.com/auth/calendar'
_TOKEN_ENDPT = 'https://accounts.google.com/o/oauth2/token'
_PATHS = {
  'cl': '/users/me/calendarList',
  'cl-id': '/users/me/calendarList/%s',
  'events': '/calendars/%s/events',
  'cal': '/calendars',
  'cal-id': '/calendars/%s',
  'acl': '/calendars/%s/acl',
  'acl-id': '/calendars/%s/acl/%s'
}

def _urlencval(val):
  """URL encode a single value."""
  return urlencode({'a': val})[2:]

def _url(urltype):
  """Get the URL path of the type given."""
  return _BASE_URL + _PATHS[urltype]

def _to_vid(mlid):
  """Convert the messaging list ID to its visual representation."""
  return ':' + mlid

def idname_arg(idname):
  """Handle ID/NAME command line argument.

  Return: tuple (type, value) where type in ['id', 'name']

  """
  if idname.startswith(':'):
    if len(idname) < 2:
      raise argparse.ArgumentTypeError(
        "'%s' is not a valid id" % idname)
    return ('id', idname[1:])
  else:
    return ('name', idname)

def id_arg(s):
  """Handle ID command line argument."""
  if len(s) < 2 or not s.startswith(':'):
    raise argparse.ArgumentTypeError(
      "'%s' is not an id - must start with ':'" % s)
  return s[1:]

def _ml_not_found(fn):
  """Decorate to show a friendly message for 404 HTTP error."""
  def wrapped_fn(*args, **kwargs):
    try:
      return fn(*args, **kwargs)
    except HTTPError as e:
      if e.code == 404:
        raise MessagingListNotFound()
      else:
        raise
  return wrapped_fn

class Request(_Request):
  """Request with HTTP method as a configurable property.

  From: http://stackoverflow.com/a/6312600/319954

  """

  def __init__(self, *args, **kwargs):
    self._method = kwargs.pop('method', None)
    _Request.__init__(self, *args, **kwargs)

  def get_method(self):
    return self._method if self._method \
      else _Request.get_method(self)

class GCSMS(object):
  """High level messaging list API on top of Google Calendar API."""

  def __init__(self, client_id = '', client_secret = '',
               access_token = ''):
    """Initialize an instance of GCSMS.

    client_id -- must be acquired online from Google API Console
    client_secret -- must be acquired online from Google API Console
    access_token -- use obtain_access_token() to get access token

    """
    self.client_id = client_id
    self.client_secret = client_secret
    self.access_token = access_token

  def obtain_user_code(self):
    """Get the verification details.

    Return: {
      "device_code" : "6/asdgahdaifushdfiaublajKLFg3y",
      "user_code" : "a798sfac",
      "verification_url" : "http://www.google.com/device",
      "expires_in" : 1800,
      "interval" : 5
    }

    User should be directed to 'verification_url' and asked to enter the
    'user_code'. Meanwhile, obtain_refresh_token() should be called
    in 'interval' seconds to check if the user has granted access. As
    soon as the user does, obtain_refresh_token() will return the
    refresh token which can be used repeatedly to obtain access token,
    using obtain_access_token().

    """

    req = Request(
      _DEV_CODE_ENDPT,
      data=urlencode({
        'client_id': self.client_id,
        'scope': _SCOPE
      }).encode('utf8')
    )
    return json.loads(urlopen(req).read().decode('utf8'))

  def obtain_refresh_token(self, dev_code):
    """Get reusable refresh token after user grants access.

    dev_code -- 'device_code', from return value of
               obtain_user_code()

    obtain_user_code() should be called first to direct the user to a
    webpage that asks them to grant access. This method either throws
    AuthPending exception while the user has yet to grant access, or it
    returns -> {
      "access_token" : "a29.AwSv0HELP2J4cCvFSj-8Gr6cgXU",
      "token_type" : "Bearer",
      "expires_in" : 3600,
      "refresh_token" : "1/551G1yc8lY8CAR-Q"
    }

    """
    req = Request(
      _TOKEN_ENDPT,
      data=urlencode({
        'client_id': self.client_id,
        'client_secret': self.client_secret,
        'code': dev_code,
        'grant_type': _GRANT_TYPE
      }).encode('utf8')
    )
    rtres = json.loads(urlopen(req).read().decode('utf8'))
    error = rtres.get('error', None)
    refresh_token = rtres.get('refresh_token', None)
    if error in ('slow_down', 'authorization_pending'):
      raise AuthPending()
    elif error:
      raise GCSMSError("got auth error '%s'" % error)
    elif refresh_token:
      return refresh_token
    else:
      # XXX need a better error reporting here
      raise GCSMSError('unexpected error')

  def obtain_access_token(self, refresh_token):
    """Get access token that's needed for API calls to work.

    refresh_token -- 'refresh_token' from return value of
                     obtain_refresh_token().
    Return: access_token as string

    In order for other methods of this class to work, access_token
    attribute of GCSMS instance must be set to return value of this
    method.

    """
    req = Request(
      _TOKEN_ENDPT,
      data=urlencode({
        'client_id': self.client_id,
        'client_secret': self.client_secret,
        'refresh_token': refresh_token,
        'grant_type': 'refresh_token'
      }).encode('utf8')
    )
    tres = json.loads(urlopen(req).read().decode('utf8'))
    access_token = tres.get('access_token', None)
    if access_token is None:
      raise GCSMSError("cannot get access token - try reauthenticating")
    return access_token

  def create(self, name):
    """Create a new messaging list.

    name -- human readable name

    Return: the ID of new messaging list

    """
    mlid = self._call_api(
      _url('cal') + '?fields=id',
      method='POST',
      body={
        'summary': _MLNAME_PREFIX + name
      }
    )['id']
    self._call_api(
      _url('cl-id') % _urlencval(mlid),
      method='PATCH',
      body={
        'hidden': True,
        'selected': False,
        'defaultReminders': [],
        'summaryOverride': _MLNAME_PREFIX + name
      }
    )
    return mlid

  @_ml_not_found
  def join(self, mlid, name = None):
    """Join a messaging list.

    mlid -- id
    name -- name to assign to the messaging list

    Return: @name if set, otherwise the name of the ML as set by its
            owner

    """
    self._call_api(
      _url('cl') + '?fields=id',
      method='POST',
      body={'id': mlid}
    )

    if name is not None:
      overridename = _MLNAME_PREFIX + name
    else:
      cl = self._call_api(
        (_url('cl-id') % _urlencval(mlid)) + '?fields=summary'
      )
      if cl['summary'].startswith(_MLNAME_PREFIX):
        overridename = cl['summary']
      else:
        overridename = _MLNAME_PREFIX + cl['summary']
    
    self._call_api(
      (_url('cl-id') % _urlencval(mlid)) + '?fields=id',
      method='PUT',
      body={
        'hidden': True,
        'selected': False,
        'defaultReminders': [],
        'summaryOverride': overridename.strip()
      }
    )

    return overridename

  @_ml_not_found
  def leave(self, mlid):
    """Leave a messaging list."""
    self._call_api(_url('cl-id') % _urlencval(mlid), method='DELETE')

  @_ml_not_found
  def destroy(self, mlid):
    """Delete a messaging list you own."""
    self._call_api(_url('cal-id') % _urlencval(mlid), method='DELETE')

  @_ml_not_found
  def send(self, mlid, msg, delay = 0):
    """Send a message to a messaging list.

    mlid -- the ML's id
    msg -- text message
    delay -- number of seconds from now to schedule the message

    """

    try:
      ts = datetime.utcfromtimestamp(
        time.time() + 65 + delay).isoformat(b'T') + 'Z'
    except TypeError:
      ts = datetime.utcfromtimestamp(
        time.time() + 65 + delay).isoformat('T') + 'Z'

    self._call_api(
      _url('events') % _urlencval(mlid),
      method='POST',
      body={
        'start': {'dateTime': ts},
        'end': {'dateTime': ts},
        'summary': msg,
        'transparency': 'transparent'
      }
    )

  @_ml_not_found
  def rename(self, mlid, newname):
    """Rename a messaging list."""
    # TODO rename the calendar as well if allowed
    self._call_api(
      _url('cl-id') % _urlencval(mlid),
      method='PATCH',
      body={
        'summaryOverride': _MLNAME_PREFIX + newname
      }
    )

  def mlists(self):
    """Get the list of all messaging lists we have joined.

    Return: [{
      'id': '2342dffgsda@asdfa.com',
      'name': 'humand-readable-name',
      'access': <one of 'reader', 'writer', 'owner'>,
      'muted': True/False
    }, ...
    ]

    """
    items = self._call_api(
      _url('cl') +
      '?minAccessRole=reader&maxResults=1000000&showHidden=True'
      '&fields=items(accessRole,defaultReminders,id,summaryOverride)'
    )['items']

    items = filter(
      lambda x: x.get('summaryOverride', '').startswith(_MLNAME_PREFIX),
      items
    )

    return map(lambda x: {
      'id': x['id'],
      'name': x['summaryOverride'][len(_MLNAME_PREFIX):].strip(),
      'access': x['accessRole'],
      'muted': {'method': 'sms', 'minutes': 1} not in
               x.get('defaultReminders', [])
    }, items)

  @_ml_not_found
  def mute(self, mlid, mute = True):
    """Stop/Start receiving SMS from messaging list.

    mute -- True for stopping, and False for starting

    """
    self._call_api(
      _url('cl-id') % _urlencval(mlid),
      method='PATCH',
      body={
        'defaultReminders':
          [] if mute else [{'method': 'sms', 'minutes': 1}]
      }
    )

  @_ml_not_found
  def acl(self, mlid):
    """Get the access control list.

    Return: [{
      'type': <one of 'domain', 'user', 'group'>,
      'address': <email address or domain name>,
      'access': <one of 'reader', 'writer', 'owner'>
    }, ...
    ]

    """
    res = self._call_api(
      (_url('acl') % _urlencval(mlid))
        + '?items(id,role,scope)&maxResults=1000000'
    )['items']
    return map(lambda x: {
      'type': x['scope']['type'],
      'address': x['scope']['value'],
      'id': x['id'],
      'access': x['role']
    }, res)

  @_ml_not_found
  def aclset(self, mlid, address, addtype, access):
    """Set access level for a particular address.

    mlid -- messaging list id
    address -- email address or domain name
    addtype -- one of 'domain', 'user', 'group'
    access -- one of 'reader', 'writer', 'owner'

    """
    scope = {'type': addtype}
    if addtype != 'default':
      scope['value'] = address
    self._call_api(
      _url('acl') % _urlencval(mlid),
      method='POST',
      body={'role': access, 'scope': scope}
    )

  def aclrm(self, mlid, address, addtype):
    """Remove access leve for a particular address.

    mlid -- messaging list id
    address -- email address or domain name
    addtype -- one of 'domain', 'user', 'group'

    """
    acl = self.acl(mlid)
    for aclitem in acl:
      if (addtype == 'default' and aclitem['type'] == 'default') \
          or (aclitem['address'] == address):
        self._call_api(
          _url('acl-id')
            % (_urlencval(mlid), _urlencval(aclitem['id'])),
          method='DELETE'
        )

  def _call_api(self, url, method = 'GET', body = None):
    """Make a calendar API call.

    url -- end point of the API, use _url()
    method -- HTTP method to use
    body -- JSON body of the request

    """

    req = Request(
      url,
      method=method,
      data=json.dumps(body).encode('utf8') if body else None,
      headers={
        'X-HTTP-Method-Override': method,
        'Authorization': 'Bearer %s' % self.access_token,
        'Content-type': 'application/json'
      }
    )
    response = urlopen(req).read().decode('utf8')
    if method == 'DELETE':
      return None
    else:
      return json.loads(response)

class GCSMSError(Exception):
  """GCSMS specific exceptions."""
  pass

class MultipleMatch(GCSMSError):
  """A human readable messaging list name had multiple matches.

  First argument is set to list of IDs of all messaging lists matched.
  
  """
  pass

class AuthPending(GCSMSError):
  """Waiting for user to grant access to the API."""
  pass

class MessagingListNotFound(GCSMSError):
  """Messaging list not found."""
  pass

def _cmd_create(args, cfg, inst):
  mlid = inst.create(args.name)
  print(_to_vid(mlid))

def _cmd_join(args, cfg, inst):
  name = inst.join(args.id, args.name)

def _cmd_ls(args, cfg, inst):
  mls = list(inst.mlists())
  mls.sort(key=lambda x: x['name'].lower())
  for ml in mls:
    mlid = '  ' + _to_vid(ml['id']) if args.long else ''
    access, name = '', ml['name']
    if args.long:
      access = {
        'reader': 'r--',
        'writer': 'rw-',
        'owner': 'rwo'
      }[ml['access']] + ('m' if ml['muted'] else '-') + '  '
    print('%s%s%s' % (access, name, mlid))

def _cmd_mute(args, cfg, inst):
  mlid = _get_id_for_idname(inst, args.idname)
  inst.mute(mlid, True)

def _cmd_unmute(args, cfg, inst):
  mlid = _get_id_for_idname(inst, args.idname)
  inst.mute(mlid, False)

def _cmd_leave(args, cfg, inst):
  mlid = _get_id_for_idname(inst, args.idname)
  inst.leave(mlid)

def _cmd_rm(args, cfg, inst):
  inst.destroy(args.id)

def _cmd_send(args, cfg, inst):
  mlid = _get_id_for_idname(inst, args.idname)
  msg = sys.stdin.read() if args.msg is None else args.msg
  inst.send(mlid, msg, delay=args.delay)

def _cmd_rename(args, cfg, inst):
  mlid = _get_id_for_idname(inst, args.idname)
  inst.rename(mlid, args.newname)

def _cmd_log(args, cfg, inst):
  raise GCSMSError('NOT IMPLEMENTED YET')

def _cmd_acl_ls(args, cfg, inst):
  mlid = _get_id_for_idname(inst, args.idname)
  acl = inst.acl(mlid)
  acl.sort(key=lambda x: x['address'])
  for aclitem in acl:
    access = {
      'none': '---',
      'freeBusyReader': '---',
      'reader': 'r--',
      'writer': 'rw-',
      'owner': 'rwo'
    }[aclitem['access']]
    address = '[public]' if aclitem['type'] == 'default' \
      else aclitem['address']
    print('%s  %s' % (access, address))

def _cmd_acl_set(args, cfg, inst):
  mlid = _get_id_for_idname(inst, args.idname)
  if args.address == 'public':
    addtype = 'default'
    if args.access != 'reader':
      raise GCSMSError("public can only have 'reader' access")
  else:
    addtype = 'user' if '@' in args.address else 'domain'
  inst.aclset(mlid, args.address, addtype, args.access)

def _cmd_acl_rm(args, cfg, inst):
  mlid = _get_id_for_idname(inst, args.idname)
  if args.address == 'public':
    addtype = 'default'
  else:
    addtype = 'user' if '@' in args.address else 'domain'
  address = '' if args.address == 'public' else args.address
  acl = inst.aclrm(mlid, address, addtype)

def _get_id_for_idname(inst, idname):
  t, v = idname
  if t == 'id':
    return v
  mls = filter(lambda x: x['name'].lower() == v.lower(), inst.mlists())
  mls = list(mls)
  if len(mls) == 0:
    raise GCSMSError("no messaging lists matched name '%s'" % v)
  elif len(mls) > 1:
    raise MultipleMatch(map(lambda x: x['id'], mls))
  else:
    return mls[0]['id']

def _cmd_auth(args, cfg, inst):
  """Authenticate with Google."""

  ucres = inst.obtain_user_code()

  print("Visit %s\nand enter the code '%s'\n"
        "Waiting for you to grant access ..."
        % (ucres['verification_url'], ucres['user_code']))

  while True:
    try:
      refresh_token = inst.obtain_refresh_token(ucres['device_code'])
    except AuthPending as e:
      time.sleep(int(ucres['interval']))
    else:
      break

  # Store the refresh token in the config file

  cfg.set(_GLOBAL, 'refresh_token', refresh_token)
  cfg.write(open(args.config + ".tmp", 'w'))
  os.rename(args.config + ".tmp", args.config)

  print("Successful.")

def main():
  """Parse command line args and run appropriate command."""

  def add_idname(p):
    p.add_argument(
      'idname',
      metavar='ID/NAME',
      type=idname_arg,
      help='id or name of the messaging list'
    )

  parser = argparse.ArgumentParser(
    formatter_class=argparse.RawDescriptionHelpFormatter,
    description='Send SMS for free using Google Calendar'
  )
  parser.add_argument(
    '-c', '--config',
    default=os.path.expanduser('~/.gcsms'),
    metavar='FILE',
    help='path to config file - default is ~/.gcsms'
  )
  subparsers = parser.add_subparsers(
    title='main commands',
    dest='cmd'
  )

  parser_a = subparsers.add_parser(
    'auth',
    help='authenticate with Google'
  )

  parser_a = subparsers.add_parser(
    'join',
    help='join a messaging list'
  )
  parser_a.add_argument(
    'id',
    metavar='ID',
    type=id_arg,
    help='id of the messaging list'
  )
  parser_a.add_argument(
    'name',
    metavar='NAME',
    nargs='?',
    default=None,
    type=unicode,
    help='name under which to add this messaging list'
  )

  parser_a = subparsers.add_parser(
    'leave',
    help='leave a messaging list'
  )
  add_idname(parser_a)

  parser_a = subparsers.add_parser(
    'create',
    help='create a new messaging list and return its id'
  )
  parser_a.add_argument(
    'name',
    metavar='NAME',
    type=unicode,
    help='name of the new messaging list'
  )

  parser_a = subparsers.add_parser(
    'rm',
    help='delete a messaging list'
  )
  parser_a.add_argument(
    'id',
    metavar='ID',
    type=id_arg,
    help='id of the messaging list'
  )

  parser_a = subparsers.add_parser(
    'mute',
    help='stop receiving SMS from messaging list'
  )
  add_idname(parser_a)

  parser_a = subparsers.add_parser(
    'unmute',
    help='start receiving SMS from messaging list'
  )
  add_idname(parser_a)

  parser_a = subparsers.add_parser(
    'ls',
    help='list all messaging lists subscribed to'
  )
  parser_a.add_argument(
    '-l', '--long',
    action='store_true',
    help='show access and other details'
  )

  parser_a = subparsers.add_parser(
    'send',
    help='send an SMS to messaging list'
  )
  add_idname(parser_a)
  parser_a.add_argument(
    'msg',
    metavar='MSG',
    nargs='?',
    default=None,
    type=unicode,
    help='SMS message to send - if not specified, read from stdin'
  )
  parser_a.add_argument(
    '-d', '--delay',
    metavar='N',
    default=0,
    type=int,
    help='delay delivery by N seconds - default is no delay'
  )

  parser_a = subparsers.add_parser(
    'rename',
    help='rename a messaging list'
  )
  add_idname(parser_a)
  parser_a.add_argument(
    'newname',
    metavar='NAME',
    type=unicode,
    help='new name'
  )

  parser_a = subparsers.add_parser(
    'log',
    help='message log'
  )
  add_idname(parser_a)

  parser_a = subparsers.add_parser(
    'acl-set',
    help="set user/domain access to messaging list - use 'public'"
         " to set public access"
  )
  add_idname(parser_a)
  parser_a.add_argument(
    'address',
    metavar='ADDRESS',
    type=unicode,
    help='address of user/domain'
  )
  parser_a.add_argument(
    'access',
    metavar='ACCESS',
    choices=['reader', 'writer', 'owner'],
    type=unicode,
    help='access level - one of reader, writer, owner'
  )

  parser_a = subparsers.add_parser(
    'acl-rm',
    help='revoke user/domain access to messaging list'
  )
  add_idname(parser_a)
  parser_a.add_argument(
    'address',
    metavar='ADDRESS',
    type=unicode,
    help='address of user/domain'
  )

  parser_a = subparsers.add_parser(
    'acl-ls',
    help='list all users/domains granted access to messaging list'
  )
  add_idname(parser_a)

  args = parser.parse_args()

  try:

    cfg = _load_config(args.config)

    inst = GCSMS(client_id = cfg.get(_GLOBAL, 'client_id'),
                 client_secret = cfg.get(_GLOBAL, 'client_secret'))

    try:

      # Get access token

      if args.cmd != 'auth':
        try:
          refresh_token = cfg.get(_GLOBAL, 'refresh_token')
        except NoOptionError:
          raise GCSMSError(
            "you must first run 'gcsms auth' to authenticate")
        inst.access_token = inst.obtain_access_token(refresh_token)

      globals()['_cmd_' + args.cmd.replace('-', '_')](args, cfg, inst)

    except HTTPError as e:
      if e.code == 403:
        raise GCSMSError("you don't have permission to do that")
      elif e.code // 100 == 5:
        raise GCSMSError('server error: %s' % e.reason)
      else:
        raise
    except MessagingListNotFound as e:
      raise GCSMSError('messaging list not found')
    
  except MultipleMatch as e:
    print('%s: multiple messaging lists matched - use id' % _PROGNAME,
          file=sys.stderr)
    for mlid in e.args[0]:
      print('  ' + _to_vid(mlid), file=sys.stderr)
    exit(1)
  except GCSMSError as e:
    print('%s: error: %s' % (_PROGNAME, e.args[0]), file=sys.stderr)
    exit(1)
  except KeyboardInterrupt:
    print('%s: keyboard interrupt' % _PROGNAME)
    exit(1)

def _load_config(path):
  """Load the configuration file."""

  cfg = SafeConfigParser()
  if os.path.exists(path):
    cfg.read(path)
  else:
    raise GCSMSError("config file doesn't exist")

  try:
    cfg.get(_GLOBAL, 'client_id')
    cfg.get(_GLOBAL, 'client_secret')
  except (NoOptionError, NoSectionError):
    raise GCSMSError(
      '"client_id" and/or "client_secret" is missing in config')

  return cfg

if __name__ == '__main__':
  main()
