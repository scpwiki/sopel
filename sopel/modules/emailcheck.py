# coding=utf-8
"""
emailcheck.py - Watch oper messages for new nicks being registered
Copyright © 2021, Kufat <kufat@kufat.net>
Based on existing sopel code.
Licensed under the Eiffel Forum License 2.
"""

import logging
import re
import urllib

import sqlalchemy.sql

from dataclasses import dataclass

from sopel import db, module
from sopel.config.types import FilenameAttribute, StaticSection, ValidatedAttribute, ListAttribute
from sopel.tools import events, target, Identifier

from sqlalchemy import Column, String, Float, Boolean, TIMESTAMP
from sqlalchemy.ext.declarative import declarative_base

try:
    from ip import get_exemption
except:
    def get_exemption(ip):
        return "Can't access exemptions; failing safe"

EMAIL_REGEX = re.compile(r"([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)")
IRCCLOUD_USER_REGEX = re.compile(r"[us]id[0-9]{4,}")
DOMAIN_LEN = 50

DEFAULT_EXEMPT_SUFFIXES = {
    "@gmail.com",
    "@hotmail.com",
    "@protonmail.com",
    ".edu"
}

KILL_STR = ":Use of disposable email service for nick registration"

LOGGER = logging.getLogger(__name__)

BASE = declarative_base()

#SQLAlchemy container class
class KnownEmails(BASE):
    __tablename__ = 'known_emails'
    domain = Column(String(DOMAIN_LEN), primary_key=True)
    first_nick = Column(String(40))
    score = Column(Float)
    flag_disposable = Column(Boolean)
    flag_recent_abuse = Column(Boolean)
    first_seen = Column(TIMESTAMP, server_default=sqlalchemy.sql.func.now())

class EmailCheckSection(StaticSection):
    IPQS_key = ValidatedAttribute('IPQS_key')
    disallow_threshold = ValidatedAttribute("disallow_threshold", parse=float)
    malicious_threshold = ValidatedAttribute("malicious_threshold", parse=float)
    gline_time = ValidatedAttribute('gline_time')
    #TODO; just hard-coded ones for now
    exempt_suffixes = ListAttribute("exempt_suffixes")
    warn_chans = ListAttribute("warn_chans")
    protect_chans = ListAttribute("protect_chans")

def configure(config):
    config.define_section('emailcheck', EmailCheckSection)
    config.emailcheck.configure_setting('IPQS_key',
                                        'Access key for IPQS service')
    config.emailcheck.configure_setting('disallow_threshold',
                                        'Addresses with scores >= this will be disallowed; no punishment',
                                        default=50.0)
    config.emailcheck.configure_setting('malicious_threshold',
                                        'Addresses with scores >= this will be interpreted as attacks',
                                        default=75.0)
    config.emailcheck.configure_setting('gline_time',
                                        'Users attempting to register with malicious addresses will be '
                                        'glined for this priod of time.',
                                        default="24h")
    config.emailcheck.configure_setting('exempt_suffixes',
                                        'Suffixes (TLD, whole domain, etc.) to exempt from checking')
    config.emailcheck.configure_setting('warn_chans',
                                        'List of channels to warn when a suspicious user is detected. '
                                        'May be empty.')
    config.emailcheck.configure_setting('protect_chans',
                                        'List of channels to +R after malicious attempt to reg. '
                                        'May be empty.')

def setup(bot):
    bot.config.define_section('emailcheck', EmailCheckSection)

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
    score: float
    flag_disposable: bool
    flag_recent_abuse: bool

def alert(bot, alert_msg: str, log_err: bool = False):
    for channel in config.emailcheck.warn_chans:
        bot.say(alert_msg, channel)
    if log_err:
        LOGGER.error(alert_msg)

def add_badmail(bot, email):
    #Right now we're BADMAILing whole domains. This might change.
    bot.write("NICKSERV", "badmail", "add", f'*@{email.domain}')

def fdrop(bot, nick: str):
    bot.write("NICKSERV", "fdrop", nick.lower())

def gline_ip(bot, ip: str, duration: str):
    bot.write("GLINE", f'*@{ip}', duration, KILL_STR)

def gline_username(bot, nick: str, duration: str):
    if known_user := bot.users.get(Identifier(nick)):
        username = known_user.user.lower() # Should already be lowercase
        if IRCCLOUD_USER_REGEX.match(username):
            bot.write("GLINE", f'{username}@*', duration, KILL_STR)
            return
        else:
            alert(bot, f"User {nick} had unexpected non-IRCCloud username {username}", true)
    else:
        alert(bot, f"Couldn't find irccloud uid/sid for {nick} to G-line!", true)
    kill_nick(bot, nick) # Something went wrong with G-line, so fall back to /kill

def kill_nick(bot, nick: str):
    bot.write("KILL", nick.lower(), KILL_STR)

def gline_strategy(bot, nick):
    if (known_user := bot.users.get(Identifier(nick))):
        if hasattr(known_user, "ip"):
            ip = known_user.ip
            exemption = get_exemption(ip)
            if exemption:
                if "irccloud" in exemption.lower():
                    # IRCCloud special case: ban uid/sid
                    return ["gline_username", known_user.user]
                else: # Fully exempt, so no g-line
                    return None
            else: # No exemption
                return ["gline_ip", ip]
    else: # Fail safely
        return None

def gline_or_kill(bot, nick: str, duration: str):
    if strategy := gline_strategy(bot, nick):
        if strategy[0] == "gline_ip":
            gline_ip(bot, strategy[1], duration)
        elif strategy[0] == "gline_username":
            gline_username(bot, strategy[1], duration)
        else:
            alert(bot, f"Unknown strategy {strategy} for nick {nick}", true)
            kill_nick(bot, nick) # safest option
    else:
        kill_nick(bot, nick) # duration ignored

def protect_chans(bot):
    for chan in config.emailcheck.protect_chans:
        bot.write("MODE", chan, "+R")

def malicious_response(bot, nick: str, email):
    fdrop(bot, nick)
    add_badmail(bot, email)
    bot.say(f"You have been temporarily banned from this network because {email.domain} "
             "has a history of spam or abuse, and/or is a disposable email domain. "
             "If this is a legitimate domain, contact staff for assistance.",
             nick.lower())
    gline_or_kill(bot, nick, config.emailcheck.gline_time)
    protect_chans(bot)
    alert(bot, f"ALERT: User {nick} attempted to register a nick with disposable/spam domain {email.domain}!")

def disallow_response(bot, nick: str, email):
    fdrop(bot, nick)
    add_badmail(bot, email)
    bot.say(f"Your registration has been disallowed because {email.domain} appears to be suspicious. "
             "If this is a legitimate domain, contact staff for assistance.",
             nick.lower())
    alert(bot, f"WARNING: User {nick} attempted to register a nick with suspicious domain {email.domain}.")

def fetch_IPQS_email_score(
    email_addr: str,
    key: str,
    fast: bool = True
    ) -> tuple[float, bool, bool]: #score, disposable, has recent abuse flag set
    '''Perform lookup on a specific email adress using ipqualityscore.com'''
    email_str = urllib.parse.quote(email_addr)
    faststr = str(bool(fast)).lower() #lower + handle None and other garbage
    params = urllib.parse.urlencode({'fast': faststr})
    with urllib.request.urlopen(
        f"https://ipqualityscore.com/api/json/email/{key}/{email_str}?{params}") as url:
            data = json.loads(url.read().decode())
            LOGGER.debug(data)
    if not data['success']:
        errstr = f"{email_addr} lookup failed with {data['message']}"
        LOGGER.error(errstr)
        raise RuntimeError(errstr)
    return (data['fraud_score'], data["disposable"], data["recent_abuse"])

def get_email_score_from_db(session, email):
    query_result = session.query(KnownEmails)\
        .filter(KnownEmails.domain == email.domain)\
        .one_or_none()
    if query_result:
        #Any known problematic provider should've been BADMAILed by now, but...
        return DomainInfo(query_result.score,
                          query_result.flag_disposable,
                          query_result.flag_recent_abuse)

def store_email_score_in_db(session, email, nick, IPQSresult):
    new_known_email = KnownEmails(domain= email.doman[:DOMAIN_LEN],
                                    first_nick= nick,
                                    score= IPQSresult[0],
                                    flag_disposable= IPQSresult[1],
                                    flag_recent_abuse= IPQSresult[2])
    session.add(new_known_email)
    session.commit()

def retrieve_score(bot, email, nick):
    session = bot.db.ssession()
    try:
        if retval := get_email_score_from_db(session, email):
            return retval
        else:
            if IPQSresult := fetch_IPQS_email_score(email, config.emailcheck.IPQS_key):
                store_email_score_in_db(session, email, nick, IPQSresult)
                return IPQSresult
            else: #Shouldn't be possible
                raise RuntimeError(f"Couldn't retrieve IPQS for {email}!")
    except SQLAlchemyError:
        session.rollback()
        raise
    finally:
        session.remove()

def check_email(bot, email, nick):
    if any(map(email.endswith, DEFAULT_EXEMPT_SUFFIXES)):
        #email is exempt
        LOGGER.info(f'Email {email} used by {nick} is on the exemption list.')
        return None # No lookup, no result
    #Check database
    else:
        return retrieve_score(bot, email, nick)

# <NickServ> ExampleAccount REGISTER: ExampleNick to foo@example.com
# (note the 0x02 bold chars)
@module.rule(r'(\S*)\s*REGISTER: \u0002?([\S]+?)\u0002? to \u0002?(\S+)@(\S+?)\u0002?$')
@module.event("PRIVMSG")
@module.priority("high")
def handle_ns_register(bot, trigger):
    if "nickserv" != trigger.sender.lower():
        LOGGER.warning(f"Fake registration notice from {trigger.sender.lower()}!")
        return
    #It's really from nickserv.
    _, nick, email_user, email_domain = trigger.groups()
    email = Email(email_user, email_domain)
    try:
        if res := check_email(bot, email_user, email_domain, nick): #may be None, in which case we're done
            if res.flag_disposable or (
                res.score >= config.emailcheck.malicious_threshold):
                malicious_response(bot, nick, email)
            elif res.flag_recent_abuse or (
                res.score >= config.emailcheck.disallow_threshold):
                disallow_response(bot, nick, email)
            else:
                #already logged server response
                return LOGGER.debug(f'Registration of {nick} to {email} OK.')
    except:
        alert(f"Lookup for f{nick} with email @f{domain} failed! Keep an eye on them.")

