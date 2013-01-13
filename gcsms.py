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

########################################################################
# DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG
########################################################################

import ssl
realssl = ssl.SSLSocket

class SSLSocketDebugger(realssl):
  def __init__(self, *args, **kwargs):
    realssl.__init__(self, *args, **kwargs)

  def send(self, *args, **kwargs):
    data = kwargs.get('data', None) or args[0]
    sys.stderr.write(data)
    return realssl.send(self, *args, **kwargs)

  def read(self, *args, **kwargs):
    data = realssl.read(self, *args, **kwargs)
    sys.stderr.write(data)
    return data

#ssl.SSLSocket = SSLSocketDebugger #uncomment to see SSL traffic

########################################################################
# END OF DEBUG
########################################################################

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
  'TODO': 'TODO'
}

def _urlencval(val):
  return urlencode({'a': val})[2:]

def _url(urltype):
  return _BASE_URL + _PATHS[urltype]

def _to_vid(mlid):
  return ':' + mlid

def idname_arg(idname):
  if idname.startswith(':'):
    if len(idname) < 2:
      raise argparse.ArgumentTypeError(
        "'%s' is not a valid id" % idname)
    return ('id', idname[1:])
  else:
    return ('name', idname)

def id_arg(s):
  if len(s) < 2 or not s.startswith(':'):
    raise argparse.ArgumentTypeError(
      "'%s' is not an id - must start with ':'" % s)
  return s[1:]

class Request(_Request):
  """Request with HTTP method as configurable property.

  From: http://stackoverflow.com/a/6312600/319954

  """

  def __init__(self, *args, **kwargs):
    self._method = kwargs.pop('method', None)
    _Request.__init__(self, *args, **kwargs)

  def get_method(self):
    return self._method if self._method \
      else _Request.get_method(self)

class GCSMS(object):

  def __init__(self, client_id = '', client_secret = '',
               access_token = ''):
    self.client_id = client_id
    self.client_secret = client_secret
    self.access_token = access_token

  def obtain_user_code(self):
    req = Request(
      _DEV_CODE_ENDPT,
      data=urlencode({
        'client_id': self.client_id,
        'scope': _SCOPE
      }).encode('utf8')
    )
    return json.loads(urlopen(req).read().decode('utf8'))

  def obtain_refresh_token(self, dev_code):
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

  def join(self, mlid, name = None):
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
        overridename = cl['summary'][len(_MLNAME_PREFIX):]
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

  def leave(self, mlid):
    self._call_api(_url('cl-id') % _urlencval(mlid), method='DELETE')

  def destroy(self, mlid):
    self._call_api(_url('cal-id') % _urlencval(mlid), method='DELETE')

  def send(self, mlid, msg, delay = 0):

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

  def rename(self, mlid, newname):
    self._call_api(
      _url('cl-id') % _urlencval(mlid),
      method='PATCH',
      body={
        'summaryOverride': _MLNAME_PREFIX + newname
      }
    )

  def mlists(self):
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

  def mute(self, mlid, mute = True):
    self._call_api(
      _url('cl-id') % _urlencval(mlid),
      method='PATCH',
      body={
        'defaultReminders':
          [] if mute else [{'method': 'sms', 'minutes': 1}]
      }
    )

  def acl(self, mlid):
    res = self._call_api(
      (_url('acl') % _urlencval(mlid))
        + '?items(id,role,scope)&maxResults=1000000'
    )['items']
    return map(lambda x: {
      'address': x['scope']['value'],
      'id': x['id'],
      'access': x['role']
    }, res)

  def _call_api(self, url, method = 'GET', body = None):
    """Make a calendar API call.

    urltype -- access URL type
    body -- JSON request body

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
  pass

class AuthPending(GCSMSError):
  pass

def _cmd_create(args, cfg, inst):
  mlid = inst.create(args.name)
  print(_to_vid(mlid))

def _cmd_join(args, cfg, inst):
  name = inst.join(args.id, args.name)

def _cmd_ls(args, cfg, inst):
  mls = list(inst.mlists())
  mls.sort(cmp=lambda x,y: cmp(x['name'].lower(), y['name'].lower()))
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
  for aclitem in acl:
    access = {
      'none': '---',
      'freeBusyReader': '---',
      'reader': 'r--',
      'writer': 'rw-',
      'owner': 'rwo'
    }[aclitem['access']]
    print('%s  %s' % (access, aclitem['address']))

def _cmd_acl_add(args, cfg, inst):
  raise GCSMSError('NOT IMPLEMENTED YET')

def _cmd_acl_rm(args, cfg, inst):
  raise GCSMSError('NOT IMPLEMENTED YET')

def _get_id_for_idname(inst, idname):
  t, v = idname
  if t == 'id':
    return idname
  mls = filter(lambda x: x['name'].lower() == v.lower(), inst.mlists())
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
    'acl-add',
    help='grant user/domain access to messaging list'
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
    choices=['read', 'write', 'owner'],
    type=unicode,
    help='access level - one of read, write, owner'
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
      else:
        raise e
    
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
