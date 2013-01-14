WHAT
==========

gcsms allows you to programmatically send SMS for free to anyone who has
a Google account. gcsms is written to present Google Calendars as
messaging lists, something akin to regular mailing lists, where users
who subscribe receive all the messages sent to the mailing list. In this
case, anyone who is subscribed to a messaging list will receive SMSes.
gcsms uses Google Calendar API v3 to create/delete calendars and events.
Everything that gcsms can do, can also be done through Google Calendar's
web interface. 

WHY
==========

Initially, this project came to being to cut on costs of monitoring the
health of a website by making use of the free SMS notification service
offered by Google Calendar, instead of using an SMS gateway like twilio
or tropo. Bells and whistles, such as ability to send to multiple
recipients was later added in order to create a generic multipurpose
tool.

HOW
==========

There are various scenarios in which gcsms can be used. We start with
the most simple one and build on that later on.

Scenario A
----------
You want to get an SMS every time your website returns a 5xx HTTP code.

You must set up a few things before using gcsms to send
SMS:

1. Setup a Google account if you don't already have one
   - https://gmail.com
2. In Google Calendar (https://calendar.google.com),
   under 'Calendar Settings' -> 'Mobile Setup', enter your mobile number
   and verify it.
3. In API Console (https://code.google.com/apis/console), under
   Services, enable 'Calendar API'.
4. In API Console, under 'API Access', create a new
   'Client ID for installed applications' with application type of
   'other' and note down the 'Client ID' and 'Client Secret'.
5. Edit '~/.gcsms' and enter the 'Client ID' and 'Client Secret' and
   save - see sample.config for the format of the config file
6. Run 'python gcsms.py auth' and follow the instructions, granting
   calendar access to gcsms.

Once you've done all the above, you can send an SMS by running:

$ echo 'Hi, I was sent from bash' | python gcsms.py send

Have patience. There might be 5 to 30 seconds delay between when you
run the above command and when you you receive the SMS. If you require a
more timely delivery, please use an SMS gateway service like twilio or
tropo.

gcsms creates a dedicated calendar named 'gcsms' in which it adds an
event for everytime you run the 'send' command. As of now, the events
remain in your calendar unless you manually delete them. If you wish to
delete all the events that gcsms has created, simply delete the
aforementioned calendar. gcsms will recreate the calendar if it needs
to.

From time to time, you might have to run 'python gcsms.py auth' to
reauthenticate with Google. This is a pain but there is no way around
it. Otherwise, enjoy.


