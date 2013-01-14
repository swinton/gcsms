What is gcsms?
==============

gcsms allows you to programmatically send SMS for free to anyone who has
a Google account. gcsms is written to present Google Calendars as
messaging lists, something akin to regular mailing lists, where users
who subscribe receive all the messages sent to the mailing list. In this
case, anyone who is subscribed to a messaging list will receive SMSes.
gcsms uses Google Calendar API v3 to create/delete calendars and events.
Everything that gcsms can do, can also be done through Google Calendar's
web interface. 

Why bother?
===========

Initially, this project came to being to cut on costs of monitoring the
health of a website by making use of the free SMS notification service
offered by Google Calendar, instead of using an SMS gateway like twilio
or tropo. Bells and whistles, such as ability to send to multiple
recipients was later added in order to create a generic multipurpose
tool.

Sold. How do I do it?
=====================

There are various scenarios in which gcsms can be used. We start with
the most simple one and build on that.

Scenario A (single subscriber)
------------------------------
You want to get an SMS every time your website returns a 5xx HTTP code.

You must set up a few things before using gcsms to send SMS:

1. Setup a Google account if you don't already have one
   (https://gmail.com).
2. In Google Calendar (https://calendar.google.com),
   under 'Calendar Settings' -> 'Mobile Setup', enter your mobile number
   and verify it.
3. In API Console (https://code.google.com/apis/console), under
   Services, enable 'Calendar API'.
4. In API Console, under 'API Access', create a new
   'Client ID for installed applications' with application type of
   'other' and note down the 'Client ID' and 'Client Secret'.
5. Edit `~/.gcsms` and enter the 'Client ID' and 'Client Secret' and
   save - see `sample.config` for the format of the config file
6. Run `python gcsms.py auth` and follow the instructions, granting
   calendar access to gcsms.

At this point, you no longer need to use the web interface - everything
can be done using gcsms commands. To avoid typing `python gcsms.py`, you
should put a link to gcsms.py in one of the appropriate directories in
`PATH`. Here's one way to do it, assuming `gcsms.py` is in your home
directory:

    $ GCSMS=~/gcsms.py
    $ chmod +x $GCSMS
    $ mkdir -p ~/bin
    $ ln -s $GCSMS ~/bin/gcsms
    $ echo 'export PATH="$PATH:~/bin"' >> ~/.bashrc

Let's create a new messaging list (ie Calendar):

    $ gcsms create web-health
    :hwernow_235nkjg@group.calendar.google.com

That long and ugly output that starts with `:` is the messaging list ID.
It's unique and is the preferred way of referring to messaging lists
when using gcsms in other scripts for automation. IDs always start with
`:`. Also, you can have multiple messaging lists with identical names
but each will have a unique ID.

You can see a list of all the messaging lists you have joined (which
includes all the ones you create/own):

    $ gcsms ls
    web-health

Using `ls` with `-l` option gives you a more detailed view:

    $ gcsms ls -l
    rwom  web-health  :hwernow_235nkjg@group.calendar.google.com

The first three letters indicate your access to the messaging list:

*  `r` means you can receive messages
*  `w` means you can send messages
*  `o` means you can manage other people's access and also delete the
   messaging list (using `gcsms rm`) which will delete it for everyone

`m` indicates that the messaging list is silenced (muted). In this mode,
you will not receive any SMSes until you _unmute_ the messaging list:

    $ gcsms unmute web-health
    $ gcsms ls -l
    rwo-  web-health  :hwernow_235nkjg@group.calendar.google.com

_Note: All messaging lists you create or join are muted by default._

At this stage, you can send yourself a message:

    $ gcsms send web-health 'Site down: 502'

You should receive an SMS shortly after the above command returns. But
have patience. There might be 5 to 30 seconds delay or sometimes more.
From time to time, you may receive multiple copies of the same message.
Unfortunately the promptness of the delivery cannot be controlled and if
your application requires a more timely delivery, you should consider an
SMS gateway service like twilio.

Scenario B (multiple subscribers)
---------------------------------

Alice, your business partner would also like to know when the website is
not feeling well.

First, Alice needs to do the steps to set up her API access (see the six
steps in scenario A). Next, you need to give her access to your
messaging list:

    [you]$ gcsms acl-set web-health alice.cooper@veryimp.bizo reader

The above command gives Alice permission to _only_ receive messages.

Alice needs to join your messaging list. She will need its unique ID.
You can find that out by using `gcsms ls -l`. Once Alice has the ID, she
can join and subsequently unmute the newly joined messaging list, ready
to receive SMSes:

    [alice]$ gcsms join :hwernow_235nkjg@group.calendar.google.com
    [alice]$ gcsms unmute web-health

