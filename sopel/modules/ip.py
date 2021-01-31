# coding=utf-8
"""
ip.py - Sopel GeoIP Lookup Module
Copyright 2011, Dimitri Molenaars, TyRope.nl,
Copyright © 2013, Elad Alfassa <elad@fedoraproject.org>
Licensed under the Eiffel Forum License 2.

https://sopel.chat
"""

from __future__ import unicode_literals, absolute_import, print_function, division

import ipaddress
import logging
import os
import socket
import tarfile
import typing

import geoip2.database
import re
import urllib.request, json

import sqlalchemy.sql

from random import randint
from urllib.request import urlretrieve

#from minfraud import Client

from sopel import module
from sopel.config.types import FilenameAttribute, StaticSection, ValidatedAttribute, ListAttribute
from sopel.tools import web, events, target, Identifier

from sqlalchemy import Column, Integer, String, Float, Boolean, TIMESTAMP, Text
from sqlalchemy.ext.declarative import declarative_base

IRCCLOUD_IP = [
    "2001:67c:2f08::/48",
    "2a03:5180:f::/64",
    "5.254.36.56/29",
    "192.184.8.73",
    "192.184.8.103",
    "192.184.9.108",
    "192.184.9.110",
    "192.184.9.112",
    "192.184.10.9",
    "192.184.10.118",
    ]

IRCCLOUD_REASON = "IRCCloud"

MIBBIT_IP = [
    "207.192.75.252",
    "64.62.228.82",
    "78.129.202.38",
    "109.169.29.95"
    ]

MIBBIT_REASON = "Mibbit"

#Hardcoded for safety
EXEMPT_IP = [
    ("104.248.43.234", "Lazar, DigitalOcean"),
    ("13.59.180.136", "War_ Limnoria bot"),
    ("138.68.23.34", "Approved bot (Idlebot, aismallard)"),
    ("18.132.171.104", "TARS"),
    ("3.136.223.150", "bluesoul"),
    ("54.174.11.206", "Helen"),
    ("69.115.75.7", "Kufat and bots"),
    ("94.159.196.226", "docazra, longtime user, IP is on dnsbl"),
    ("2604:a880:2:d0::250:9001", "Approved bot (Idlebot, aismallard)"),
    ("91.132.86.177", "bluesoul's bouncer"),
    ("2001:470:1f07:13b::/64", "kufat's tunnelbroker"),
    ]

LOGGER = logging.getLogger(__name__)
who_reqs = {}  # Keeps track of reqs coming from this plugin, rather than others

# This dict will mostly be used as a list (walking each element) but having it as a dict
# is useful for preventing duplicate entries.
exemptions = {ipaddress.ip_network(i):reason for i, reason in EXEMPT_IP}
exemptions.update(( (ipaddress.ip_network(i), IRCCLOUD_REASON) for i in IRCCLOUD_IP))
exemptions.update(( (ipaddress.ip_network(i), MIBBIT_REASON) for i in MIBBIT_IP))

BASE = declarative_base()

# This table will only receive inserts, not updates.
class KnownIPs(BASE):
    __tablename__ = 'known_ips'
    ip = Column(String(50), primary_key=True, unique=True, index=True)
    score = Column(Float)
    flag_recent_abuse = Column(Boolean)
    flag_is_proxy = Column(Boolean)
    insert_time = Column(TIMESTAMP, server_default=sqlalchemy.sql.func.now())

class ExemptIPs(BASE):
    __tablename__ = 'exempt_ips'
    ip = Column(String(50), primary_key=True, unique=True, index=True)
    # Define type of exemption.
    # GLine username e.g. uid123@* if true, no g-line at all if false. For IRCCloud.
    gline_username = Column(Boolean)
    exempt_reason = Column(Text)

# Existing rows in this table will be updated when a user is seen
# from the same nick/IP combination.
# TODO Deferred feature.
class KnownUsers(BASE):
    __tablename__ = 'known_users'
    nick = Column(String(40), primary_key=True)
    ip = Column(String(50), primary_key=True)
    cloaked_host = Column(String(40))
    last_seen = Column(TIMESTAMP, server_default=sqlalchemy.sql.func.now())

class GeoipSection(StaticSection):
    GeoIP_db_path = FilenameAttribute('GeoIP_db_path', directory=True)
    """Path of the directory containing the GeoIP database files."""
    IPQS_key = ValidatedAttribute('IPQS_key')
    warn_threshold = ValidatedAttribute('warn_threshold', parse=float)
    malicious_threshold = ValidatedAttribute('malicious_threshold', parse=float)
    warn_chans = ListAttribute("warn_chans")
    protect_chans = ListAttribute("protect_chans")

def configure(config):
    config.define_section('ip', GeoipSection)
    config.ip.configure_setting('GeoIP_db_path',
                                'Path of the GeoIP db files')
    config.ip.configure_setting('IPQS_key',
                                'Access key for IPQS service')
    config.ip.configure_setting('warn_threshold',
                                'Addresses with scores >= this will generate an alert',
                                default=50.0)
    config.ip.configure_setting('malicious_threshold',
                                'Addresses with scores >= this will be z-lined',
                                default=70.0)
    config.ip.configure_setting('warn_chans',
                                'List of channels to warn when a suspicious user is detected. '
                                'May be empty.')
    config.ip.configure_setting('protect_chans',
                                'List of channels to +R after malicious attempt to reg. '
                                'May be empty.')


def setup(bot):
    bot.config.define_section('ip', GeoipSection)

def alert(bot, alert_msg: str, log_err = False):
    for channel in config.ip.warn_chans:
        bot.say(alert_msg, channel)
    if log_err:
        LOGGER.error(alert_msg)

def get_exemption(host):
    if isinstance(host, ip.IPv4Address) or isinstance(host, ip.IPv6Address):
        host = ip
    else:
        try:
            ip = ipaddress.ip_address(socket.getaddrinfo(host, None)[0][4][0])
        except:
            raise
    for network, reason in exemptions.items():
        if ip in network:
            return reason
    return None

def fetch_IPQS_score(
    ip_addr: typing.Union[ipaddress.IPv4Address, ipaddress.IPv6Address],
    key: str,
    allow_public_access_points: bool = True,
    strictness: int = 1,
    fast: bool = False,
    mobile: bool = False
    ) -> tuple[float, bool, bool]: #score, is proxy, has recent abuse flag set
    '''Perform lookup on a specific IP adress using ipqualityscore.com'''
    params = urllib.parse.urlencode({
        'allow_public_access_points': "true" if allow_public_access_points else "false",
        'strictness': int(strictness),
        # lowercase + handle None and other non-bool garbage
        'fast': "true" if fast else "false",
        'mobile': "true" if mobile else "false",
        })
    # ip_addr sourced from server, not user, so sanitization already done
    with urllib.request.urlopen(
        f"https://ipqualityscore.com/api/json/ip/{key}/{str(ip_addr)}?{params}") as url:
        data = json.loads(url.read().decode())
        LOGGER.info(data)
    if not data['success']:
        errstr = f"{ip_addr} lookup failed with {data['message']}"
        LOGGER.error(errstr)
        raise RuntimeError(errstr)
    return (data['score'], data["proxy"], data["recent_abuse"])

def get_ip_score_from_db(session, ip):
    query_result = session.query(KnownIPs)\
        .filter(KnownIPs.ip == str(ip))\
        .one_or_none()
    if query_result:
        #Any known problematic provider should've been BADMAILed by now, but...
        return (query_result.score,
                query_result.flag_recent_abuse,
                query_result.flag_proxy
                )

def store_ip_score_in_db(session, ip, nick, IPQSresult):
    new_known_ip = KnownEmails(ip= ip,
                               score= IPQSresult[0],
                               flag_recent_abuse= IPQSresult[1],
                               flag_is_proxy= IPQSresult[2])
    session.add(new_known_ip)
    session.commit()

def retrieve_score(bot, ip, nick, do_fetch = True):
    session = bot.db.ssession()
    try:
        if retval := get_ip_score_from_db(session, ip):
            return retval
        elif do_fetch:
            if IPQSresult := fetch_IPQS_ip_score(ip, config.emailcheck.IPQS_key):
                store_ip_score_in_db(session, ip, nick, IPQSresult)
                return IPQSresult
            else: #Shouldn't be possible
                raise RuntimeError("Couldn't retrieve IPQS!")
        else:
            # If do_fetch is false, this is a best-effort request and shouldn't use up a query
            return None
    except SQLAlchemyError:
        session.rollback()
        raise
    finally:
        session.remove()

def _add_exemption(ip, reason):
    exemptions[ipaddress.ip_network(ip)] = reason

def _decompress(source, target, delete_after_decompression=True):
    """Decompress just the database from the archive"""
    # https://stackoverflow.com/a/16452962
    tar = tarfile.open(source)
    for member in tar.getmembers():
        if ".mmdb" in member.name:
            member.name = os.path.basename(member.name)
            tar.extract(member, target)
    if delete_after_decompression:
        os.remove(source)


def _find_geoip_db(bot):
    """Find the GeoIP database"""
    config = bot.config
    if config.ip.GeoIP_db_path:
        cities_db = os.path.join(config.ip.GeoIP_db_path, 'GeoLite2-City.mmdb')
        ipasnum_db = os.path.join(config.ip.GeoIP_db_path, 'GeoLite2-ASN.mmdb')
        if (os.path.isfile(cities_db) and os.path.isfile(ipasnum_db)):
            return config.ip.GeoIP_db_path
        else:
            LOGGER.warning(
                'GeoIP path configured but DB not found in configured path')

    if (os.path.isfile(os.path.join(config.core.homedir, 'GeoLite2-City.mmdb')) and
            os.path.isfile(os.path.join(config.core.homedir, 'GeoLite2-ASN.mmdb'))):
        return config.core.homedir
    elif (os.path.isfile(os.path.join('/usr/share/GeoIP', 'GeoLite2-City.mmdb')) and
            os.path.isfile(os.path.join('/usr/share/GeoIP', 'GeoLite2-ASN.mmdb'))):
        return '/usr/share/GeoIP'
    elif urlretrieve:
        LOGGER.info('Downloading GeoIP database')
        bot.say('Downloading GeoIP database, please wait...')

        common_params = {'license_key': 'JXBEmLjOzislFnh4', 'suffix': 'tar.gz'}
        base_url = 'https://download.maxmind.com/app/geoip_download'
        geolite_urls = []

        for edition in ['ASN', 'City']:
            geolite_urls.append(
                '{base}?{params}'.format(
                    base=base_url,
                    params=web.urlencode(dict(common_params, **{'edition_id': 'GeoLite2-%s' % edition})),
                )
            )

        for url in geolite_urls:
            LOGGER.debug('GeoIP Source URL: %s', url)
            full_path = os.path.join(config.core.homedir, url.split("/")[-1])
            urlretrieve(url, full_path)
            _decompress(full_path, config.core.homedir)
        return bot.config.core.homedir
    else:
        return False

def populate_user(bot, user, ip, host, nick):
    LOGGER.debug('Adding: %s!%s@%s with IP %s', nick, user, host, ip)

    user = bot.users.get(nick) or target.User(nick, user, host)
    if ip:
        user.ip = ip # Add nonstandard field
    bot.users[nick] = user # no-op if user was in users, needed otherwise

def examine_user(bot, user, ip, host, nick):
    populate_user(bot, user, ip, host, nick)
    res = retrieve_score(bot, ip, nick)
    if res:
        score, is_proxy, is_recent_abuse = res
        if( is_prox or is_recent_abuse or score >= config.ip.malicious_threshold ):
            alert(bot, f"Ops: Nick {nick} has abuse score {score}, proxy: {is_prox}, "
                        "recent_abuse: {is_recent_abuse}; z-lining!")
            bot.write("ZLINE", ip, "24h", f":Auto z-line {nick}.")
            protect_chans(bot)
        elif score >= config.ip.warn_threshold:
            alert(bot, f"Ops: Nick {nick} has abuse score {score}; keep an eye on them.")
    return res

@module.event(events.RPL_WHOSPCRPL)
@module.priority('high')
def recv_whox_ip(bot, trigger):
    """Track ``WHO`` responses when ``WHOX`` is enabled."""
    #LOGGER.debug('Receiving who: %s', trigger.args[1])
    if len(trigger.args) < 2 or trigger.args[1] not in who_reqs:
        # Ignored, some other plugin probably called WHO
        return
    #it's us
    # :safe.oh.us.irc.scpwiki.com 354 Kufat 0 kufat 2001:470:1f07:13b::1 gatekeeper.kufat.net :Kufat
    if len(trigger.args) != 6:
        return LOGGER.warning('While populating the IP DB, a WHO response was malformed.')
    _, _, user, ip, host, nick = trigger.args
    examine_user(bot, user, ip, host, nick)

@module.event(events.RPL_ENDOFWHO)
@module.priority('high')
def end_who_ip(bot, trigger):
    """Handle the end of a response to a ``WHO`` command (if needed)."""
    if 'WHOX' in bot.isupport:
        who_reqs.pop(trigger.args[1], None)

@module.event(events.RPL_YOUREOPER)
@module.priority('high')
def send_who(bot, _):
    if 'WHOX' in bot.isupport:
        # WHOX syntax, see http://faerion.sourceforge.net/doc/irc/whox.var
        # Needed for accounts in WHO replies. The random integer is a param
        # to identify the reply as one from this command, because if someone
        # else sent it, we have no way to know what the format is.

        # 'x' indicates uncloaked address. This is triggered by
        # RPL_YOUREOPER because that functionality is restricted to opers.
        rand = str(randint(0, 999))
        while rand in who_reqs:
            rand = str(randint(0, 999))
        LOGGER.debug('Sending who: %s', rand)
        who_reqs[rand] = True
        bot.write([r'WHO * n%nuhti,' + rand])

#:safe.oh.us.irc.scpwiki.com NOTICE Kufat :*** CONNECT: Client connecting on port 6697 (class main): ASNbot!sopel@ool-45734b07.dyn.optonline.net (69.115.75.7) [Sopel: https://sopel.chat/]
@module.rule(r'.*Client connecting .*: (\S*)!(\S*)@(\S*) \((.*)\)')
@module.event("NOTICE")
@module.priority("high")
def handle_snotice_conn(bot, trigger):
    LOGGER.debug("Saw connect line: [%s] from [%s]", trigger.raw, trigger.sender)
    #Only servers may have '.' in the sender name, so this isn't spoofable
    if "scpwiki.com" in trigger.sender:
        nick, user, host, ip = trigger.groups()
        examine_user(bot, user, ip, None, nick) #cloaked host not known
        #Be **certain** we don't waste our lookups on irccloud
        if any(host.endswith(s) for s in (".irccloud.com", ".mibbit.com")):
            return
        # We need to check if the IP is in any exempt CIDR ranges
        if get_exemption(ip):
            return

        res = examine_user(bot, user, ip, host, nick)
        if res:
            # Acted on above; just log here
            score, is_proxy, is_recent_abuse = res
            LOGGER.debug(f"handle_snotice_conn: {nick}!{user}@{host} ({ip}) had "
                          "score {score}, proxy: {is_prox}, "
                          "recent_abuse: {is_recent_abuse}")

# NICK: User Kufat-bar changed their nickname to Kufat-foo
# This is redundant for users the bot can see in-channel but needed for users with no common channel
@module.rule(r'.*User (\S+) changed their nickname to (\S+).*')
@module.event("NOTICE")
@module.priority("high")
def handle_snotice_ren(bot, trigger):
    LOGGER.debug("Saw nick change line: [%s] from [%s]", trigger.raw, trigger.sender)
    if "scpwiki.com" in trigger.sender:
        oldnick = Identifier(trigger.group(1))
        newnick = Identifier(trigger.group(2))
        if olduser := bot.users.get(oldnick):
            populate_user(bot, olduser.user, olduser.ip, olduser.host, newnick)

@module.require_privilege(module.OP)
@module.commands('ip_exempt')
@module.example('.ip_exempt 8.8.8.8')
def ip_exempt(bot, trigger):
    if not trigger.group(3):
        return bot.reply("You must specify an IP or range in CIDR format to exempt.")
    elif not trigger.group(4):
        return bot.reply("You must specify a reason for the exemption.")
    ipstr = trigger.group(3)
    if '*' in ipstr:
        return bot.reply("Use CIDR format (1.2.3.0/24) rather than wildcard format (1.2.3.*)")
    reason = trigger.group(2).lstrip(ipstr).lstrip()
    try:
        _add_exemption(ipstr, reason)
    except ValueError as e:
        return bot.reply(f"Could not add exemption for {ipstr} because: {str(e)}")

@module.require_privilege(module.HALFOP)
@module.commands('iplookup', 'ip')
@module.example('.ip 8.8.8.8',
         r'\[IP\/Host Lookup\] Hostname: \S*dns\S*\.google\S*( \| .+?: .+?)+ \| ISP: AS15169 \S+',
         re=True,
         ignore='Downloading GeoIP database, please wait...',
         online=True)
def ip(bot, trigger):
    if trigger.is_privmsg and ( trigger.account is None or trigger.account.lower() != "kufat" ):
        return
    full = ( ( trigger.sender.lower() in ("#skipirc-staff", "#kufat") ) or
    ( trigger.is_privmsg and trigger.account.lower() == "kufat" ) )
    irccloud = False
    mibbit = False
    nick = None
    """IP Lookup tool"""
    # Check if there is input at all
    if not trigger.group(2):
        return bot.reply("Usage: '.ip (Nick or address) [lookup]'. "
                         "If 'lookup' is specified, will look up IP score if not known.")
    # Check whether the input is an IP or hostmask or a nickname
    search_str = trigger.group(3) # Groups 3-6 = command args 1-4
    decide = ['.', ':']
    if any(x in search_str for x in decide):
        # It's an IP/hostname!
        query = search_str.strip()
    else:
        # Need to get the ip for the username
        nick = search_str.strip().lower()
        if user_in_botdb := bot.users.get(nick):
            if hasattr(user_in_botdb, "ip") and user_in_botdb.ip:
                query = user_in_botdb.ip
                # Sanity check - sometimes user information isn't populated yet
            else:
                return bot.say("I don't know that user's IP.")
        else:
            #TODO TODO TODO get from DB
            return bot.say("I\'m not aware of this user.")

    ex = get_exemption(query).lower()

    if ex:
        irccloud = "irccloud" in ex
        mibbit = "mibbit" in ex
    if not any((irccloud, mibbit)):
        db_path = _find_geoip_db(bot)
        if db_path is False:
            LOGGER.error('Can\'t find (or download) usable GeoIP database.')
            bot.say('Sorry, I don\'t have a GeoIP database to use for this lookup.')
            return False

        if ':' in query:
            try:
                socket.inet_pton(socket.AF_INET6, query)
            except (OSError, socket.error):  # Python 2/3 compatibility
                return bot.say("[IP/Host Lookup] Unable to resolve IP/Hostname")
        elif '.' in query:
            try:
                socket.inet_pton(socket.AF_INET, query)
            except (socket.error, socket.herror):
                try:
                    query = socket.getaddrinfo(query, None)[0][4][0]
                except socket.gaierror:
                    return bot.say("[IP/Host Lookup] Unable to resolve IP/Hostname")
        else:
            return bot.say("[IP/Host Lookup] Unable to resolve IP/Hostname")

        city = geoip2.database.Reader(os.path.join(db_path, 'GeoLite2-City.mmdb'))
        asn = geoip2.database.Reader(os.path.join(db_path, 'GeoLite2-ASN.mmdb'))
        host = socket.getfqdn(query)
        try:
            city_response = city.city(query)
            asn_response = asn.asn(query)
        except geoip2.errors.AddressNotFoundError:
            return bot.say("[IP/Host Lookup] The address is not in the database.")

    response = "[IP/Host Lookup]"

    if irccloud:
        response += " IP belongs to IRCCloud; no location data available"
        return bot.say(response)
    elif mibbit:
        response += " IP belongs to mibbit; no location data available"
        return bot.say(response)
    else:
        response += f" | IP meets exemption [{ex}] |"
        # Still look up an IP that's exempt for other reasons

    if full:
        response += " Hostname: %s |" % host

    try:
        response_loc = " Location: %s" % city_response.country.name
        region = city_response.subdivisions.most_specific.name
        response_loc += " | Region: %s" % region if region else ""

        if full:
            city = city_response.city.name
            response_loc += " | City: %s" % city if city else ""

        response += response_loc

    except AttributeError:
        response += ' Location: Unknown'

    try:
        isp = "AS" + str(asn_response.autonomous_system_number) + \
            " " + asn_response.autonomous_system_organization
        response += " | ISP: %s" % isp if isp else ""
    except:
        response += ' ISP: Unknown'

    force_lookup = trigger.group(4) == "lookup"
    res = None
    try:
        res = retrieve_score(bot, query, nick, force_lookup)
    except Exception as e:
        LOGGER.error(f"Couldn't look up IP {query} because {e}")
    if res:
        response += f" | Score: {res[0]} Proxy: {res[1]} Recent abuse detected: {res[2]}"
    elif not force_lookup:
        # Use search_str to avoid leaking an IP
        response += f" | To retrieve IP score run '.ip {search_str} lookup'"
    bot.say(response)


if __name__ == "__main__":
    from sopel.test_tools import run_example_tests
    run_example_tests(__file__)
