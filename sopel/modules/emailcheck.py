# coding=utf-8
"""
emailcheck.py - Watch oper messages for new nicks being registered
Copyright © 2021, Kufat <kufat@kufat.net>
Based on existing sopel code.
Licensed under the Eiffel Forum License 2.
"""

import json
import logging
import re
import threading
import urllib

import sqlalchemy.sql

from collections import namedtuple
from dataclasses import dataclass
from http import HTTPStatus
from typing import Tuple

from sopel import db, module
from sopel.config.types import FilenameAttribute, StaticSection, ValidatedAttribute, ListAttribute
from sopel.tools import events, target, Identifier

from sqlalchemy import Column, String, Float, Boolean, TIMESTAMP
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.declarative import declarative_base

from .ip import get_exemption, sopel_session_scope

IRCCLOUD_USER_REGEX = re.compile(r"[us]id[0-9]{4,}")
DOMAIN_LEN = 50

KILL_STR = ":Use of disposable email service for nick registration"

LOGGER = logging.getLogger(__name__)

BASE = declarative_base()

email_safe_mode = True

pizza_lock = threading.Lock()

ValidatorPizzaResponse = namedtuple('ValidatorPizzaResponse',
    ['flag_valid', 'flag_disposable'])

GLineStrategy = namedtuple('GLineStrategy', ['strategy', 'targer'])

#SQLAlchemy container class
class KnownEmails(BASE):
    __tablename__ = 'known_emails'
    domain = Column(String(DOMAIN_LEN), primary_key=True, index=True)
    first_nick = Column(String(40))
    flag_valid = Column(Boolean)
    flag_disposable = Column(Boolean, nullable=False)
    first_seen = Column(TIMESTAMP, server_default=sqlalchemy.sql.func.now())

class EmailCheckSection(StaticSection):
    gline_time = ValidatedAttribute('gline_time', default='24h')
    warn_chans = ListAttribute('warn_chans')
    protect_chans = ListAttribute('protect_chans')

def configure(config):
    config.define_section('emailcheck', EmailCheckSection)
    config.emailcheck.configure_setting('gline_time',
                                        'Users attempting to register with malicious addresses will be '
                                        'glined for this priod of time.')
    config.emailcheck.configure_setting('warn_chans',
                                        'List of channels to warn when a suspicious user is detected. '
                                        'May be empty.')
    config.emailcheck.configure_setting('protect_chans',
                                        'List of channels to +R after malicious attempt to reg. '
                                        'May be empty.')

def setup(bot):
    bot.config.define_section('emailcheck', EmailCheckSection)
    BASE.metadata.create_all(bot.db.engine)

@dataclass
class Email:
    user: str
    domain: str
    def get_address(self):
        return f'{self.user}@{self.domain}'
    def __str__(self):
        return self.get_address()
    def __post_init__(self):
        self.domain = self.domain.lower()

@dataclass
class DomainInfo:
    flag_valid: bool
    flag_disposable: bool

def alert(bot, alert_msg: str, log_err: bool = False):
    for channel in bot.config.emailcheck.warn_chans:
        bot.say(alert_msg, channel)
    if log_err:
        LOGGER.error(alert_msg)

def add_badmail(bot, email):
    #Right now we're BADMAILing whole domains. This might change.
    if email_safe_mode:
        LOGGER.info(f"SAFE MODE: Would badmail {email}")
    else:
        bot.write("NICKSERV", "badmail", "add", f'*@{email.domain}')

def fdrop(bot, nick: str):
    if email_safe_mode:
        LOGGER.info(f"SAFE MODE: Would fdrop {nick}")
    else:
        bot.write("NICKSERV", "fdrop", nick.lower())

def gline_ip(bot, ip: str, duration: str):
    if email_safe_mode:
        LOGGER.info(f"SAFE MODE: Would gline {ip} for {duration}")
    else:
        bot.write("GLINE", f'*@{ip}', duration, KILL_STR)

def gline_irccloud(bot, nick: str, duration: str):
    if known_user := bot.users.get(Identifier(nick)):
        username = known_user.user.lower() # Should already be lowercase
        if IRCCLOUD_USER_REGEX.match(username):
            if email_safe_mode:
                LOGGER.info(f"SAFE MODE: Would gline {username} for {duration}")
            else:
                bot.write("GLINE", f'{username}@*', duration, KILL_STR)
            return
        else:
            alert(bot, f"User {nick} had unexpected non-IRCCloud username {username}", true)
    else:
        alert(bot, f"Couldn't find irccloud uid/sid for {nick} to G-line!", true)
    kill_nick(bot, nick) # Something went wrong with G-line, so fall back to /kill

def kill_nick(bot, nick: str):
    if email_safe_mode:
        LOGGER.info(f"SAFE MODE: Would kill {nick}")
    else:
        bot.write("KILL", nick.lower(), KILL_STR)

def gline_strategy(bot, nick):
    if (known_user := bot.users.get(Identifier(nick))):
        if hasattr(known_user, "ip"):
            ip = known_user.ip
            exemption = get_exemption(ip)
            if exemption:
                if "irccloud" in exemption.lower():
                    # IRCCloud special case: ban uid/sid
                    return GLineStrategy("gline_irccloud", known_user.user)
                else: # Fully exempt, so no g-line
                    return None
            else: # No exemption
                return GLineStrategy("gline_ip", ip)
    else: # Fail safely
        return None

def gline_or_kill(bot, nick: str, duration: str):
    if gline_strat := gline_strategy(bot, nick):
        if gline_strat.strategy == "gline_ip":
            gline_ip(bot, strategy.target, duration)
        elif gline_strat.strategy == "gline_irccloud":
            gline_irccloud(bot, strategy.target, duration)
        else:
            alert(bot, f"Unknown strategy {strategy} for nick {nick}", true)
            kill_nick(bot, nick) # safest option
    else:
        kill_nick(bot, nick) # duration ignored

def protect_chans(bot):
    if email_safe_mode:
        LOGGER.info(f"SAFE MODE: Would protect chans")
        return
    for chan in bot.config.emailcheck.protect_chans:
        bot.write("MODE", chan, "+R")
    alert(bot, f"Setting {', '.join(bot.config.emailcheck.protect_chans)} +R")

def malicious_response(bot, nick: str, email):
    fdrop(bot, nick)
    add_badmail(bot, email)
    bot.say(f"You have been temporarily banned from this network because {email.domain} "
             "has a history of spam or abuse, and/or is a disposable email domain. "
             "If this is a legitimate domain, contact staff for assistance.",
             nick.lower())
    gline_or_kill(bot, nick, bot.config.emailcheck.gline_time)
    protect_chans(bot)
    alert(bot, f"ALERT: User {nick} attempted to register a nick with disposable/spam domain {email.domain}!")

def disallow_response(bot, nick: str, email):
    fdrop(bot, nick)
    add_badmail(bot, email)
    bot.say(f"Your registration has been disallowed because {email.domain} appears to be suspicious. "
             "If this is a legitimate domain, contact staff for assistance.",
             nick.lower())
    alert(bot, f"WARNING: User {nick} attempted to register a nick with suspicious domain {email.domain}.")

def fetch_validator_pizza_email_info(email_addr: str ) \
-> Tuple[bool, bool]: #valid, disposable
    '''Perform lookup on a specific email adress using validator.pizza'''
    email_addr_str = urllib.parse.quote(str(email_addr))
    # Cloudflare likes headers. Sigh.
    hdr = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11',
       'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
       'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
       'Accept-Encoding': 'none',
       'Accept-Language': 'en-US,en;q=0.8',
       'Connection': 'keep-alive'}
    urlstr = f"https://www.validator.pizza/email/{email_addr_str}"
    req = urllib.request.Request(urlstr, headers=hdr)
    try:
        with pizza_lock, urllib.request.urlopen(req) as url:
                data = json.loads(url.read().decode())
                LOGGER.debug(f"Received data from validator.pizza: {data}")
    except urllib.error.HTTPError as err:
        LOGGER.error(f"Error retrieving {urlstr}: {err.code}, {err.headers}")
        raise
    if data['status'] == HTTPStatus.OK:
        return ValidatorPizzaResponse(data['mx'], data["disposable"])
    elif data['status'] == HTTPStatus.BAD_REQUEST:
        # Address is invalid, assume typo
        return ValidatorPizzaResponse(False, None)
    elif data['status'] == HTTPStatus.TOO_MANY_REQUESTS:
        # This is unlikely enough that I'm going to postpone dealing with it
        raise RuntimeError("Hit request limit!")
    else: # Anything other than 200/400/429 is out of spec
        errstr = f"{email_addr} lookup failed with {data}"
        LOGGER.error(errstr)
        raise RuntimeError(errstr)

def get_email_info_from_db(session, email):
    query_result = session.query(KnownEmails)\
        .filter(KnownEmails.domain == email.domain)\
        .one_or_none()
    if query_result:
        #Any known problematic provider should've been BADMAILed by now, but...
        return DomainInfo(query_result.flag_valid,
                          query_result.flag_disposable)

def store_email_info_in_db(session, email, nick, result):
    new_known_email = KnownEmails(domain= email.domain[:DOMAIN_LEN],
                                  first_nick= nick,
                                  flag_valid= result.flag_valid,
                                  flag_disposable= result.flag_disposable)
    session.add(new_known_email)

def retrieve_info_for_email(bot, email, nick):
    session = bot.db.ssession()
    with sopel_session_scope(bot) as session:
        if retval := get_email_info_from_db(session, email):
            return retval
        else:
            if result := fetch_validator_pizza_email_info(email):
                store_email_info_in_db(session, email, nick, result)
                return result
            else:
                #Should either return or throw
                raise RuntimeError(f"validator.pizza failed for email: {email}")

@module.require_owner
@module.commands('toggle_safe_email')
def toggle_safe(bot, trigger):
    global safe_mode
    safe_mode = not safe_mode
    return bot.reply(f"Email check module safe mode now {'ON' if safe_mode else 'OFF'}")

# <NickServ> ExampleAccount REGISTER: ExampleNick to foo@example.com
# (note the 0x02 bold chars)
@module.rule(r'(\S*)\s*REGISTER: \u0002?([\S]+?)\u0002? to \u0002?(\S+)@(\S+?)\u0002?$')
@module.event("PRIVMSG")
@module.priority("high")
def handle_ns_register(bot, trigger):
    if "nickserv" != trigger.nick.lower():
        LOGGER.warning(f"Fake registration notice from {trigger.nick.lower()}!")
        return
    #It's really from nickserv.
    _, nick, email_user, email_domain = trigger.groups()
    email = Email(email_user, email_domain)
    try:
        # check_email() may return None, in which case we're done
        if res := retrieve_info_for_email(bot, email, nick):
            if res.flag_disposable:
                malicious_response(bot, nick, email)
            elif not res.flag_valid :
                disallow_response(bot, nick, email)
            else:
                #already logged server response
                return LOGGER.debug(f'Registration of {nick} to {email} OK.')
    except:
        alert(bot, f"Lookup for {nick} with email @{email_domain} failed! "
                    "Keep an eye on them.")
        raise
