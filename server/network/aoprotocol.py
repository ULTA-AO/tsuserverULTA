"""
tsuserverOLE, an Attorney Online server.
Copyright (C) 2021 KillerSteel <killermagnum5@gmail.com

Derivative of tsuserverCC, an Attorney Online server.
Copyright (C) 2020 Kaiser <kaiserkaisie@gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.
 
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.
 
You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""


import time
import asyncio
import re
import unicodedata

import logging

logger_debug = logging.getLogger('debug')
logger = logging.getLogger('events')

import arrow
from time import localtime, strftime

from server import database
from server.statements import Statement
from server.exceptions import ClientError, AreaError, ArgumentError, ServerError
from server.fantacrypt import fanta_decrypt
from .. import commands
from server.network.packets import features_fl
from server.network.validator_parameters import *


class AOProtocol(asyncio.Protocol):
    """The main class that deals with the AO protocol."""

    #Feature flags
    flpacket = features_fl()
    #Sets of parameters for IC message validators:
    msgpre260 = validator_pre260()
    msg270 = validator_270()
    msg290 = validator_290()
    msg211 = validator_211()
    msgulta5 = validator_ulta5()

    # Oldest ULTA protocol still parsed
    ULTA_OLDEST_SUPPORTED = 5

    # Narration: "folder;scene;name" (narrator folder, scene 0 = over own character, 1 = alone).
    # The name must not contain packet delimiters (# % & $) or field separators.
    # Optional last part is a scene token (see net_cmd_ms): [bw][oi]h? = black/white fade (h = hold),
    # t<2-20> = narrator overlay
    testimony_cmd_re = re.compile(r'^(//.*|/end|\+.*|<and>.*|>{1,2}\d*|<{1,2}|={1,2})$', re.DOTALL)
    ulta_narration_re =re.compile(r'^([A-Za-z0-9_]{1,32});([01]);([^;#%&$<>|\\\r\n]{1,24})(;(?:[bw][oi]h?|t(?:[2-9]|1[0-9]|20)))?$')

    # Character fade of the speaker's sprite: o = fade out after the line, i = fade in at the start
    ulta_charfx_re = re.compile(r'^[oiO]$')

    # Custom color palette: "slot:rrggbb" entries, comma separated. No "#" before the hex, it is the
    # packet separator
    ulta_palette_re = re.compile(r'^\d{1,2}:[0-9a-fA-F]{6}(,\d{1,2}:[0-9a-fA-F]{6})*$')
    ULTA_PALETTE_MAX_ENTRIES = 12   # the client has 12 color slots (c0..c11)




    def __init__(self, server):
        super().__init__()
        self.server = server
        self.client = None
        self.buffer = ''
        self.ping_timeout = None

    def dezalgo(self, input):
        """
        Turns any string into a de-zalgo'd version,
        with a tolerance to allow for normal diacritic use.
    
    
    
    
    
    
    
        The following Unicode blocks are scrubbed:
        U+0300 - U+036F - COMBINING DIACRITICAL MARKS
        U+1AB0 - U+1AFF - COMBINING DIACRITICAL MARKS EXTENDED
        U+1DC0 - U+1DFF - COMBINING DIACRITICAL MARKS SUPPLEMENT
        U+20D0 - U+20FF - COMBINING DIACRITICAL MARKS FOR SYMBOLS
        U+FE20 - U+FE2F - COMBINING HALF MARKS
        """
    
        filtered = re.sub('([\u0300-\u036f\u1ab0-\u1aff\u1dc0-\u1dff\u20d0-\u20ff\ufe20-\ufe2f]' +
                          '{' + re.escape(str(self.server.zalgo_tolerance)) + ',})',
                          '', input)
        return filtered
        
    def data_received(self, data):
        """Handles any data received from the network.

        Receives data, parses them into a command and passes it
        to the command handler.

        :param data: bytes of data

        """
        buf = data
        ipid = self.client.ipid

        if buf is None:
            buf = b''

        if not isinstance(buf, str):
            # try to decode as utf-8, ignore any erroneous characters
            self.buffer += buf.decode('utf-8', 'ignore')
        else:
            self.buffer = buf

        self.buffer = self.buffer.translate({ord(c): None for c in '\0'})

        if len(self.buffer) > 8192:
            self.client.disconnect()
        for msg in self.get_messages():
            if len(msg) < 2:
                continue
            # general netcode structure is not great
            if msg[0] in ('#', '3', '4'):
                if msg[0] == '#':
                    msg = msg[1:]
                spl = msg.split('#', 1)
                msg = '#'.join([fanta_decrypt(spl[0])] + spl[1:])
            try:
                cmd, *args = msg.split('#')
                self.net_cmd_dispatcher[cmd](self, args)
            except KeyError:
                logger_debug.debug(f'Unknown incoming message from {ipid}: {msg}')

    def connection_made(self, transport):
        """Called upon a new client connecting

        :param transport: the transport object

        """
        try:
            self.client = self.server.new_client(transport)
        except ClientError:
            transport.close()
            return
        if not self.server.client_manager.new_client_preauth(self.client):
            self.client.send_command('BD', 'Maximum clients reached.\nDisconnect one of your clients to continue.')
            self.client.disconnect()
            return
        # Client needs to send CHECK#% within the timeout - otherwise,
        # it will be automatically dropped.
        self.ping_timeout = asyncio.get_event_loop().call_later(
            self.server.config['timeout'], self.client.disconnect)
        asyncio.get_event_loop().call_later(0.25, self.client.send_command,
                                            'decryptor',
                                            34)     # just fantacrypt things)
        

    def connection_lost(self, exc):
        """User disconnected

        :param exc: reason

        """
        if self.client is not None:
            logger.debug(f'{self.client.ipid} disconnected.')
            self.server.remove_client(self.client)
        if self.ping_timeout is not None:
            self.ping_timeout.cancel()

    def get_messages(self):
        """Parses out full messages from the buffer.
        
        :return: yields messages

        """
        while '#%' in self.buffer:
            spl = self.buffer.split('#%', 1)
            self.buffer = spl[1]
            yield spl[0]

    def validate_net_cmd(self, args, *types, needs_auth=True):
        """Makes sure the net command's arguments match expectations.

        :param args: actual arguments to the net command
        :param types: what kind of data types are expected
        :param needs_auth: whether you need to have chosen a character (Default value = True)
        :param *types: list of types corresponding to each argument in the command
        :returns: returns True if message was validated

        """
        if needs_auth and self.client.char_id == -1:
            return False
        if len(args) != len(types):
            return False
        for i, arg in enumerate(args):
            if len(arg) == 0 and types[i] != ArgType.STR_OR_EMPTY:
                return False
            if types[i] == ArgType.INT:
                try:
                    args[i] = int(arg)
                except ValueError:
                    return False
        return True

    def net_cmd_hi(self, args):
        """
        Handshake.
        
        HI#<hdid:string>#%

        :param args: a list containing all the arguments

        """
        if not self.validate_net_cmd(args, ArgType.STR, needs_auth=False):
            return
        hdid = self.client.hdid = args[0]
        ipid = self.client.ipid

        database.add_hdid(ipid, hdid)
        ban = database.find_ban(ipid, hdid)
        if ban is not None:
            
            if ban.unban_date is not None:
                unban_date = arrow.get(ban.unban_date)
            else:
                unban_date = 'N/A'
    
            msg = f'{ban.reason}\r\n'
            msg += f'ID: {ban.ban_id}\r\n'
            
            if unban_date == 'N/A':
                msg += f'Until: {unban_date}'
            else:
                msg += f'Until: {unban_date.humanize()}'
    
            database.log_connect(self.client, failed=True)
            self.client.send_command('BD', msg)
            self.client.disconnect()
            return
            
        else:
            self.client.is_checked = True

        database.log_connect(self.client, failed=False)
        self.client.send_command('ID', self.client.id, self.server.software,
                                 self.server.version)
        self.client.send_command('PN',
                                 self.server.player_count,
                                 self.server.config['playerlimit'])
        # Send the feature list here too. Stock 2.10 clients send askchaa before their ID reply, so SI
        # can arrive before FL and the courtroom is built without the features
        self.client.send_command(*AOProtocol.flpacket)

        # Optional: require the ULTA AO client (config `ulta_required`).
        if self.server.config.get('ulta_required', False):
            timeout = float(self.server.config.get('ulta_handshake_timeout', 8))
            asyncio.get_event_loop().call_later(
                timeout, self._enforce_ulta_required, self.client)

    def _enforce_ulta_required(self, client):
        """Disconnect a client that never did the ULTA handshake.

        Not a security measure (the handshake can be imitated); it just keeps
        out ordinary players on other clients when the server owner wants an
        ULTA-only server. Uses BD because it is the one packet every stock
        client shows as a dialog in any state; the message says it's not a ban.
        """
        if client.ulta_version > 0:
            return
        if not self.server.config.get('ulta_required', False):
            return
        if client.transport.is_closing():
            return
        msg = str(self.server.config.get(
            'ulta_required_message',
            'This server requires the ULTA AO client (you are NOT banned).'))
        # '#' and '%' are AO packet delimiters.
        msg = msg.replace('#', '<num>').replace('%', '<percent>')
        logger.info(f'ULTA required: disconnecting non-ULTA client id={client.id}')
        client.send_command('BD', msg)
        asyncio.get_event_loop().call_later(1.0, client.disconnect)

    ULTA_PALETTE_INDEX = 38  # position of the palette in the outgoing MS fields

    # Client version as reported in the ULTA handshake, e.g. 1.0.2 or 1.0.2-beta.
    ulta_client_version_re = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}(-[A-Za-z0-9.]{1,12})?$')

    @staticmethod
    def _version_tuple(version):
        """'1.0.10-beta' -> (1, 0, 10); anything else -> (0, 0, 0)."""
        try:
            parts = [int(p) for p in str(version).split('-')[0].split('.')]
        except ValueError:
            return (0, 0, 0)
        return tuple((parts + [0, 0, 0])[:3])

    @staticmethod
    def _ulta_flag_statement(args):
        """Mark an MS as a testimony statement: the palette field gets a leading
        "s" entry. ULTA clients then keep the statement's base color (green)
        and apply the sender's palette only to inline color spans."""
        i = AOProtocol.ULTA_PALETTE_INDEX
        if len(args) > i:
            p = str(args[i])
            if p != 's' and not p.startswith('s,'):
                args[i] = 's' if p == '-' else 's,' + p
        return args

    @staticmethod
    def _ulta_flag_title(args):
        """Testimony title: the palette field becomes "t", which tells ULTA
        clients to show it in the stock colors, whatever any palette says."""
        i = AOProtocol.ULTA_PALETTE_INDEX
        if len(args) > i:
            args[i] = 't'
        return args

    def _ulta_scene_tools_allowed(self, area):
        """Whether narrators may use scene tools in this area.

        Config `ulta_scene_tools`: off | rooms (default: only rooms created
        inside a hub) | hubs (hub areas and their rooms) | everywhere.
        """
        mode = str(self.server.config.get('ulta_scene_tools', 'rooms')).lower()
        if mode == 'everywhere':
            return True
        if mode == 'off':
            return False
        in_room = getattr(area, 'hub', None) is not None
        if mode == 'hubs':
            return in_room or bool(getattr(area, 'is_hub', False))
        return in_room  # 'rooms' (and anything unrecognised: the safe default)

    def _ulta_scene_tools_denied_text(self, what):
        """Explains why `what` (e.g. 'Flashbacks') is refused in this area."""
        mode = str(self.server.config.get('ulta_scene_tools', 'rooms')).lower()
        if mode == 'off':
            return "{} are turned off on this server.".format(what)
        if mode == 'hubs':
            return "{} can only be used in hubs and the rooms made in them.".format(what)
        return "{} can only be used in rooms made inside a hub.".format(what)

    def net_cmd_id(self, args):
        """
        Client version and PV.

        Sends the FL packet that consists of a list of
        features supported by the server.
        
        Disconnects the client if webAO is not allowed on the server config and the client is a webAO user

        Also sends ASSET packet for WebAO content 
        if asset_url in config.yaml is defined. 
        
        ID#<pv:int>#<software:string>#<version:string>#%
        """
    
        self.client.send_command(*AOProtocol.flpacket)

        # Capability: 2.11+ AO2 clients understand the 'custom_blips' IC fields.
        try:
            ver = tuple(int(x) for x in str(args[1]).split('.')[:3])
        except (IndexError, ValueError):
            ver = ()
        self.client.supports_custom_blips = (args[0] == 'AO2' and ver >= (2, 11, 0))

        if not self.server.config['allow_webao'] and args[0] == 'webAO':
            self.client.send_command('BD', 'WebAO is not allowed on this server.')
            self.client.disconnect()

        if self.server.config['asset_url'] != '':
            self.client.send_command('ASS', self.server.config['asset_url'])

    def net_cmd_ulta(self, args):
        """ULTA AO2 capability reply, sent only by ULTA clients after they
        see 'ulta_ext' in the FL packet. Stock clients never send this.

        ULTA#<protocol_version:int>#<client version, e.g. 1.0.2 (optional)>#%
        """
        try:
            ver = int(args[0])
        except (IndexError, ValueError):
            return
        ver = max(0, min(ver, 1000))
        client_version = ''
        if len(args) > 1 and AOProtocol.ulta_client_version_re.match(args[1]):
            client_version = args[1]
        # Minimum protocol (config `ulta_min_version`), too old means told to update
        min_ver = max(AOProtocol.ULTA_OLDEST_SUPPORTED,
                      int(self.server.config.get('ulta_min_version', AOProtocol.ULTA_OLDEST_SUPPORTED)))
        if ver < min_ver:
            logging.getLogger('events').info(
                f'ULTA client too old: id={self.client.id} protocol={ver} (minimum {min_ver})')
            msg = str(self.server.config.get(
                'ulta_update_message',
                'Your ULTA AO client is out of date. Please download the new version.'))
            msg = msg.replace('#', '<num>').replace('%', '<percent>')
            self.client.send_command('BD', msg)
            asyncio.get_event_loop().call_later(1.0, self.client.disconnect)
            return
        # Minimum client version (config `ulta_min_client_version`, empty = off), a client that
        # reports none counts as older
        min_client = str(self.server.config.get('ulta_min_client_version', '')).strip()
        if min_client and AOProtocol._version_tuple(client_version) < AOProtocol._version_tuple(min_client):
            logging.getLogger('events').info(
                f'ULTA client too old: id={self.client.id} version={client_version or "unknown"} (minimum {min_client})')
            msg = str(self.server.config.get(
                'ulta_update_message',
                'Your ULTA AO client is out of date. Please download the new version.'))
            msg = msg.replace('#', '<num>').replace('%', '<percent>')
            self.client.send_command('BD', msg)
            asyncio.get_event_loop().call_later(1.0, self.client.disconnect)
            return
        self.client.ulta_version = ver
        self.client.ulta_client_version = client_version
        logging.getLogger('events').info(
            f'ULTA client detected: id={self.client.id} protocol={self.client.ulta_version} '
            f'version={client_version or "unknown"}')
        # Answer a held join request now that the client is identified
        if self.client.pending_askchaa and self.client.ulta_version > 0:
            self.client.pending_askchaa = False
            self.net_cmd_askchaa(None)

    def net_cmd_fb(self, args):
        """ULTA flashback: start or end the area's flashback look.

        FB#<look: s|b|->#<hold: 0|1>#%
        s = sepia, b = black and white, - = end.
        """
        if (self.client.ulta_version < 7 or self.client.char_id == -1
                or len(args) != 2 or args[0] not in ('s', 'b', '-')
                or args[1] not in ('0', '1')):
            return
        area = self.client.area
        if not self._ulta_scene_tools_allowed(area):
            self.client.send_ooc(self._ulta_scene_tools_denied_text("Flashbacks"))
            return
        flash = area.ulta_flash
        if args[0] == '-':
            if flash and flash['owner'] == self.client.char_id:
                area.ulta_flash = None
                area.ulta_flash_broadcast()
            return
        if not self.client.ulta_can_direct():
            self.client.send_ooc("Only the area's CM can use flashbacks.")
            return
        if flash and flash['hold'] and flash['owner'] != self.client.char_id:
            self.client.send_ooc("A held flashback is already running.")
            return
        area.ulta_flash = {'look': args[0], 'owner': self.client.char_id,
                           'hold': args[1] == '1'}
        area.ulta_flash_broadcast()

    def net_cmd_ch(self, _):
        """Reset the client drop timeout (keepalive).
        
        CHECK#%
        """
        self.client.send_command('CHECK')
        self.ping_timeout.cancel()
        self.ping_timeout = asyncio.get_event_loop().call_later(
            self.server.config['timeout'], self.client.disconnect)

    def net_cmd_askchaa(self, _):
        """Ask for the counts of characters/evidence/music
        
        askchaa#%
        """
        # ULTA-only server: hold the join (the SI reply makes the client build its courtroom) until
        # the client identifies as ULTA, answered from net_cmd_ulta. A stock client waits until the
        # timer shows it the notice
        if self.server.config.get('ulta_required', False) and self.client.ulta_version == 0:
            self.client.pending_askchaa = True
            return
        char_cnt = len(self.server.char_list)
        evi_cnt = 0
        music_cnt = sum([len(x) for x in self.server.music_pages_ao1])
        self.client.send_command('SI', char_cnt, evi_cnt, music_cnt)

    def net_cmd_askchar2(self, _):
        """Asks for the character list. (AO1)
        
        askchar2#%
        """
        self.client.send_command('CI', *self.server.char_pages_ao1[0])

    def net_cmd_an(self, args):
        """Asks for specific pages of the character list.
        (AO1 only; part of askchar2 sequence)
        
        AN#<page:int>#%
        """
        if not self.validate_net_cmd(args, ArgType.INT, needs_auth=False):
            return
        if len(self.server.char_pages_ao1) > args[0] >= 0:
            self.client.send_command('CI',
                                     *self.server.char_pages_ao1[args[0]])
        else:
            self.client.send_command('EM', *self.server.music_pages_ao1[0])

    def net_cmd_ae(self, _):
        """Asks for specific pages of the evidence list.
        (AO1 only; part of askchar2 sequence)
        
        AE#<page:int>#%

        """
        pass  # todo evidence maybe later

    def net_cmd_am(self, args):
        """Asks for specific pages of the music list.
        (AO1 only; part of askchar2 sequence)
        
        AM#<page:int>#%

        """
        if not self.validate_net_cmd(args, ArgType.INT, needs_auth=False):
            return
        if len(self.server.music_pages_ao1) > args[0] >= 0:
            self.client.send_command('EM',
                                     *self.server.music_pages_ao1[args[0]])
        else:
            self.client.send_done()
            self.client.send_motd()

    def net_cmd_rc(self, _):
        """Asks for the whole character list (AO2)
        
        AC#%

        """

        self.client.send_command('SC', *self.server.char_list)

    def net_cmd_rm(self, _):
        """Asks for the whole music list (AO2)
        
        AM#%

        """

        self.client.send_command('SM', *self.server.music_list_ao2)
        area_list = []
        for area in self.server.area_manager.areas:
            area_list.append(area.name)
        self.client.send_command('FA', *area_list)

    def net_cmd_rd(self, _):
        """Asks for server metadata(charscheck, motd etc.) and a DONE#% signal(also best packet)
        
        RD#%

        """

        self.client.send_done()
        self.client.send_motd()
        self.client.send_poll()
        if self.client.area.current_music:
            self.client.current_music = self.client.area.current_music
            self.client.send_command("MC", self.client.area.current_music, -1, "", 1, 0, 2)
        elif self.client.area.ambiance:
            self.client.ambiance = self.client.area.ambiance
            self.client.send_command("MC", self.client.area.ambiance, -1, "", 1, 1, 2)

    def net_cmd_cc(self, args):
        """Character selection.
        
        CC#<client_id:int>#<char_id:int>#<hdid:string>#%

        """
        if not self.validate_net_cmd(args,
                                     ArgType.INT,
                                     ArgType.INT,
                                     ArgType.STR,
                                     needs_auth=False):
            return
        elif not self.client.is_checked:
            return

        cid = args[1]
        try:
            self.client.change_character(cid)
        except ClientError:
            return

    """
    This handles the entirety of IC message handling.
    Things that could be broken out into their own functions:
    -Version handling for legacies and current version
    """

    def net_cmd_ms(self, args):
        """IC message.
        
        Refer to the implementation for details.
        -Steel: Doing some documentation on this giga-function. You'll find my stuff sprinkled about through here.
        It's mostly theorized ideas of what the code is doing as I read, with references to functions and the files they come from.
        Enjoy. And good luck.
        """

        """
        is_checked is part of the ban checking process, which is found in net_cmd_hi further up this file.
        is_muted is kind of obvious.
        can_send_message is defined in server/area_manager.py, checking to see if you can send a message in an area.
        """
        if not self.client.is_checked:
            return
        elif self.client.is_muted:    # Checks to see if the client has been muted by a mod
            self.client.send_ooc('You are muted by a moderator.')
        elif not self.client.is_wlisted:
            self.client.send_ooc('You must be whitelisted from discord!')
            return
        elif not self.client.area.can_send_message(self.client):
            return
            
        statement = None

        target_area = []
        showname = ""
        charid_pair = -1
        offset_pair = ""
        nonint_pre = 0
        looping_sfx = 0
        screenshake = 0
        frame_screenshake = ""
        frame_realization = ""
        frame_sfx = ""
        additive = 0
        effect = ""
        blipname = ""
        slide = "0"
        pair_order = 0
        pair2_raw = "-1"      # ULTA: second pair partner (charid), "-1" = none
        pair2_offset = "0"    # ULTA: our offset for the second partner
        palette_raw = "-"     # ULTA v2: sender's custom text colors, "-" = none
        narration_raw = "-"   # ULTA v3: narrator mode settings, "-" = not narrating
        charfx_raw = "-"      # ULTA v5: speaker's character fade, "-" = none
        """
        Client validation for the message starts here.

        -Break off into net_cmd_validate_pre26, calling validate_net_cmd with appropriate parameters
        Looks like it runs the IC message from the client through the validator, then returns 
        """
        if self.validate_net_cmd(args, *AOProtocol.msgpre260): 
            # Pre-2.6 validation monstrosity.
            (msg_type, pre, folder, anim, text, pos, sfx, 
            anim_type, cid, sfx_delay, button, evidence, flip, 
            ding, color) = args
        
        #-Break off into net_cmd_validate_27, calling validate_net_cmd with appropriate parameters
        elif self.validate_net_cmd(args, *AOProtocol.msg270):
            # 2.7.0 validation monstrosity
            (msg_type, pre, folder, anim, text, pos, sfx, anim_type, cid, 
            sfx_delay, button, evidence, flip, ding, color, showname, 
            charid_pair, offset_pair, nonint_pre, looping_sfx, screenshake, 
            frame_screenshake, frame_realization, frame_sfx) = args
            if len(showname) > 0 and not self.client.area.showname_changes_allowed:
                self.client.send_host_message("Showname changes are forbidden in this area!")
                return
        #-Break off into net_cmd_validate_29, calling validate_net_cmd with appropriate parameters.
        #I think this is the latest set of validations... God, what a mess.
        elif self.client.ulta_version >= 5 and self.validate_net_cmd(args, *AOProtocol.msgulta5):
            # v5 message: the v3 fields plus the character fade (31 fields)
            (msg_type, pre, folder, anim, text, pos, sfx,
            anim_type, cid, sfx_delay, button, evidence, flip,
            ding, color, showname, charid_pair, offset_pair,
            nonint_pre, looping_sfx, screenshake, frame_screenshake,
            frame_realization, frame_sfx, additive, effect,
            pair2_raw, pair2_offset, palette_raw, narration_raw,
            charfx_raw) = args
            pair_args = charid_pair.split("^")
            charid_pair = int(pair_args[0])
            if (len(pair_args) > 1):
                pair_order = pair_args[1]
            if len(showname) > 0 and not self.client.area.showname_changes_allowed:
                self.client.send_host_message("Showname changes are forbidden in this area!")
                return
        elif self.validate_net_cmd(args, *AOProtocol.msg211):
            # 2.11 message: the 2.9 fields plus blipname and slide.
            (msg_type, pre, folder, anim, text, pos, sfx, 
            anim_type, cid, sfx_delay, button, evidence, flip, 
            ding, color, showname, charid_pair, offset_pair, 
            nonint_pre, looping_sfx, screenshake, frame_screenshake, 
            frame_realization, frame_sfx, additive, effect,
            blipname, slide) = args
            pair_args = charid_pair.split("^")
            charid_pair = int(pair_args[0])
            if (len(pair_args) > 1):
                pair_order = pair_args[1]
            if len(showname) > 0 and not self.client.area.showname_changes_allowed:
                self.client.send_host_message("Showname changes are forbidden in this area!")
                return
        elif self.validate_net_cmd(args, *AOProtocol.msg290):
            (msg_type, pre, folder, anim, text, pos, sfx, 
            anim_type, cid, sfx_delay, button, evidence, flip, 
            ding, color, showname, charid_pair, offset_pair, 
            nonint_pre, looping_sfx, screenshake, frame_screenshake, 
            frame_realization, frame_sfx, additive, effect) = args
            pair_args = charid_pair.split("^")
            charid_pair = int(pair_args[0])
            if (len(pair_args) > 1):
                pair_order = pair_args[1]
            if len(showname) > 0 and not self.client.area.showname_changes_allowed:
                self.client.send_host_message("Showname changes are forbidden in this area!")
                return
        else:
            return
        #Client message validation ends here.

        # Scene fade/overlay: a token on a normal narrated message. Only v4+ clients, only where the
        # config allows, else the line goes through without it
        if narration_raw != "-" and not self.client.ulta_can_direct():
            self.client.send_ooc("Only the area's CM can use narrator mode here.")
            narration_raw = "-"
        tool_match = AOProtocol.ulta_narration_re.match(narration_raw) if narration_raw != "-" else None
        tool_token = tool_match.group(4)[1:] if (tool_match and tool_match.group(4)) else ''
        is_fx = False
        if tool_token:
            ulta_ok = (self.server.config.get('ulta_narrator', True)
                       and self.client.ulta_version >= 4)
            if ulta_ok and self._ulta_scene_tools_allowed(self.client.area):
                is_fx = True
            else:
                if ulta_ok:
                    self.client.send_ooc(self._ulta_scene_tools_denied_text("Scene tools"))
                narration_raw = narration_raw.rsplit(';', 1)[0]
                tool_token = ''

        #Showname is set here, followed by an iniswap check. is_iniswap takes the client, a 'pre', the anim integer I think, folder name and sfx.
        #Considering the context, I think it's checking to see if you are iniswapped?
        #You can find is_iniswap in server/network/area_manager.py

        self.client.folder = folder

        if showname == folder:
            self.client.showname = ''
        elif showname == self.client.char_name:
            self.client.showname = ''
        else:
            self.client.showname = showname

        if self.client.area.is_iniswap(self.client, pre, anim,
                folder, sfx):
            self.client.send_ooc("Iniswap/custom emotes are blocked in this area")
            return

        #Checking if charcurse (ooc_cmd_charcurse in server/commands/character.py) Charcurse is
        if len(self.client.charcurse) > 0 and \
            folder != self.client.char_name:
            self.client.send_ooc(
                "You may not iniswap while you are charcursed!")
            return
        if not (is_fx and text.strip() == '') and not self.client.area.blankposting_allowed:
            if text == ' ':
                self.client.send_ooc(
                    "Blankposting is forbidden in this area!")
                return
            if text.isspace():
                self.client.send_ooc(
                    "Blankposting is forbidden in this area, and putting more spaces in does not make it not blankposting."
                )
                return
            if len(re.sub(r'[{}\\`|(~~)]', '', text).replace(
                    ' ', '')) < 3 and text != '<' and text != '>':
                self.client.send_ooc(
                    "While that is not a blankpost, it is still pretty spammy. Try forming sentences."
                )
                return
        if text.startswith('/a '):
            part = text.split(' ')
            try:
                abbr = part[1]
                area = self.server.area_manager.get_area_by_abbreviation(abbr)
                if self.client in area.owners:
                    target_area.append(area)
                if not target_area:
                    self.client.send_ooc(f'You don\'t own {area.name}!')
                    return
                text = ' '.join(part[2:])
            except AreaError:
                self.client.send_ooc("That does not look like a valid area ID!")
                return
        elif text.startswith('/s '):
            part = text.split(' ')
            for a in self.server.area_manager.areas:
                if a.is_hub:
                    for sub in a.subareas:
                        if self.client in sub.owners:
                            target_area.append(sub)
                if self.client in a.owners:
                    target_area.append(a)
            if not target_area:
                self.client.send_ooc('You aren\'t CMing any areas!')
                return
            text = ' '.join(part[1:])
        if msg_type not in ('chat', '0', '1'):
            return
        if sfx.startswith('../music'):
            sfx = ''
        if anim_type not in (0, 1, 2, 4, 5, 6):
            return
        if cid != self.client.char_id:
            return
        if sfx_delay < 0:
            return
        if not '4' in str(button) and "<and>" not in str(button):
            strbutton = str(button)
            if not button.isdigit():
                return
        if evidence < 0:
            return
        if ding not in (0, 1):
            return
        if color not in (0, 1, 2, 3, 4, 5, 6, 7, 8):
            return
        if len(showname) > 22:
            self.client.send_ooc("Your IC showname is way too long!")
            return
        if nonint_pre == 1:
            if button in (1, 2, 3, 4, 23):
                if anim_type == 1 or anim_type == 2:
                    anim_type = 0
                elif anim_type == 6:
                    anim_type = 5
        if self.client.area.non_int_pres_only:
            if anim_type == 1 or anim_type == 2:
                anim_type = 0
                nonint_pre = 1
            elif anim_type == 6:
                anim_type = 5
                nonint_pre = 1
        if not self.client.area.shouts_allowed and not (self.client.is_mod or self.client in self.client.area.owners):
            # Old clients communicate the objecting in anim_type.
            if anim_type == 2:
                anim_type = 1
            elif anim_type == 6:
                anim_type = 5
            # New clients do it in a specific objection message area.
            button = 0
            # Turn off the ding.
            ding = 0
        if pos != self.client.pos:
            self.client.change_position(pos, True)
        if not len(self.client.area.poslock) == 0 and not (self.client.is_mod or self.client in self.client.area.owners):
            if pos not in self.client.area.poslock:
                pos = self.client.area.poslock[0]
                self.client.send_ooc(f'Your pos isn\'t in /poslock, falling back on {pos}.')
                self.client.change_position(pos, True)
        msg = self.dezalgo(text)[:256]
        if self.client.shaken:
            msg = self.client.shake_message(msg)
        if self.client.gimp:  # If you're gimped, gimp message.
            msg = self.client.gimp_message(msg)
        if self.client.disemvowel:
            msg = self.client.disemvowel_message(msg)
        evi_real = self._evi_number(evidence)
        if evi_real and evi_real <= len(self.client.area.evi_list.evidences):
            if self.client.area.evi_list.evidences[evi_real - 1].pos != 'all':
                self.client.area.evi_list.evidences[evi_real - 1].pos = 'all'
                self.client.area.broadcast_evidence_list()

        # unnecessary anti-"ooc in ic" measure.
        #
        #if msg.lstrip().startswith('(('):
        #    msg = msg.lstrip()
        #    msg = msg.replace('((', '')
        #    msg = msg.replace('))', '')
        #    name = self.client.name
        #    if name == '':
        #        name = self.client.char_name
        #    if not msg == self.client.area.last_ooc:
        #        self.client.area.send_command('CT', name, msg)
        #        self.client.area.send_owner_command('CT', '[' + self.client.area.abbreviation + ']' +
        # name, msg)
        #        self.client.area.last_ooc = msg
        #    return

        if self.client.area.last_speaker != self.client:
            additive = 0

        # Here, we check the pair stuff, and save info about it to the client.
        # Notably, while we only get a charid_pair and an offset, we send back a chair_pair, an emote,
        # a talker offset
        # and an other offset.
        # Stacking order: 0 = speaker in front, 1 = behind, 2 = middle of a trio.
        # Stock clients only know 0/1, so charid_pair carries 0 for "middle" and ULTA clients read the
        # real value from the extra fields
        try:
            order_real = int(pair_order)
        except (TypeError, ValueError):
            order_real = 0
        if order_real not in (0, 1, 2):
            order_real = 0
        if str(pair_order) == "2":
            pair_order = "0"
        try:
            charid_pair2 = int(str(pair2_raw).split("^")[0])
        except ValueError:
            charid_pair2 = -1
        self.client.charid_pair = charid_pair
        self.client.offset_pair = offset_pair
        self.client.charid_pair2 = charid_pair2
        self.client.offset_pair2 = pair2_offset
        if anim_type not in (5, 6):
            self.client.last_sprite = anim
        self.client.flip = flip
        self.client.claimed_folder = folder
        other_offset = '0'
        other_emote = ''
        other_flip = 0
        other_folder = ''

        confirmed = False
        if self.client.firstperson and not confirmed:
            if self.client.area.last_speaker != None:
                lastspeaker = self.client.area.last_speaker
                if lastspeaker != self.client:
                    confirmed = True
                    self.client.firstpersonfallback = lastspeaker
                    charid_pair = lastspeaker.char_id
                    other_offset = lastspeaker.offset_pair
                    other_emote = lastspeaker.last_sprite
                    other_flip = lastspeaker.flip
                    other_folder = lastspeaker.claimed_folder
                    pos = lastspeaker.pos
                    if (pair_order != 0):
                        charid_pair = "{}^{}".format(charid_pair, pair_order)
                else:
                    if self.client.firstpersonfallback != None:
                        fallback = self.client.firstpersonfallback
                        fpchecked = False
                        for target in self.client.area.clients:
                            if target == fallback:
                                fpchecked = True
                                break
                        if fpchecked:
                            confirmed = True
                            charid_pair = fallback.char_id
                            other_offset = fallback.offset_pair
                            other_emote = fallback.last_sprite
                            other_flip = fallback.flip
                            other_folder = fallback.claimed_folder
                            pos = fallback.pos
                            if (pair_order != 0):
                                charid_pair = "{}^{}".format(charid_pair, pair_order)
                        else:
                            self.client.firstpersonfallback = None
            
        p1_char = -2  # char id of the confirmed first partner (if any)
        if charid_pair > -1 and not confirmed and not self.client.firstperson:
            for target in self.client.area.clients:
                # A partner is confirmed if it names the speaker in either pair slot (a trio is a
                # star, the speaker names two and each names the speaker back)
                if target.char_id == self.client.charid_pair and (target.charid_pair == self.client.char_id or target.charid_pair2 == self.client.char_id) and target != self.client and target.pos == self.client.pos:
                    confirmed = True
                    p1_char = target.char_id
                    other_offset = target.offset_pair
                    other_emote = target.last_sprite
                    other_flip = target.flip
                    other_folder = target.claimed_folder
                    if (pair_order != 0):
                        charid_pair = "{}^{}".format(charid_pair, pair_order)
                    break

        if not confirmed:
            charid_pair = -1
            #offset_pair = 0

        # Second partner: same rules as the first, and it must be someone else
        other2_charid = -1
        other2_folder = ''
        other2_emote = ''
        other2_offset = '0'
        other2_flip = 0
        if charid_pair2 > -1 and not self.client.firstperson:
            for target in self.client.area.clients:
                if (target.char_id == charid_pair2 and target != self.client
                        and target.char_id != p1_char
                        and target.pos == self.client.pos
                        and (target.charid_pair == self.client.char_id
                             or target.charid_pair2 == self.client.char_id)):
                    other2_charid = target.char_id
                    other2_folder = target.claimed_folder
                    other2_emote = target.last_sprite
                    other2_offset = target.offset_pair
                    other2_flip = target.flip
                    break
        # Custom colors: relayed only if strictly valid and allowed (`ulta_custom_colors`), malformed
        # becomes "-" and the message still goes through
        palette = "-"
        if self.server.config.get('ulta_custom_colors', True) and \
                palette_raw != "-" and len(palette_raw) <= 200 and \
                AOProtocol.ulta_palette_re.match(palette_raw):
            entries = palette_raw.split(",")[:AOProtocol.ULTA_PALETTE_MAX_ENTRIES]
            palette = ",".join(entries)
        # Narration: relayed only if strictly valid and allowed (`ulta_narrator`), else "-"
        narration = "-"
        if self.server.config.get('ulta_narrator', True) and \
                narration_raw != "-" and len(narration_raw) <= 80 and \
                AOProtocol.ulta_narration_re.match(narration_raw):
            narration = narration_raw
        # Character fade: only "o", "i" or "O", and only if allowed (`ulta_char_fade`), else "-"
        charfx = "-"
        if (self.server.config.get('ulta_char_fade', True)
                and AOProtocol.ulta_charfx_re.match(charfx_raw or "")):
            charfx = charfx_raw
        # Extra fields appended after the 32 base fields (see client_manager).
        ulta_pair_extras = [str(other2_charid), other2_folder, other2_emote,
                            str(other2_offset), other2_flip, order_real,
                            palette, narration, charfx]

        if self.client.afk:
            self.client.server.client_manager.toggle_afk(self.client)
        if self.client.afktime:
            self.client.afktime.cancel()
        if self.server.config['afk_delay'] > 0:
            self.client.afktime = asyncio.get_event_loop().call_later(self.client.server.config['afk_delay'], lambda: self.client.server.client_manager.toggle_afk(self.client))

        send_args = [msg_type, pre, folder, anim, msg,
                     pos, sfx, anim_type, cid, sfx_delay,
                     button, evi_real,
                     flip, ding, color, showname, charid_pair,
                     other_folder, other_emote, offset_pair,
                     other_offset, other_flip, nonint_pre,
                     looping_sfx, screenshake, frame_screenshake,
                     frame_realization, frame_sfx,
                     additive, effect, blipname, slide] + ulta_pair_extras
        msg2 = f'[{self.client.area.abbreviation}]{msg}'
        owner_args = [msg_type, pre, folder, anim, msg2,
                     pos, sfx, anim_type, cid, sfx_delay,
                     button, evi_real,
                     flip, ding, color, showname, charid_pair,
                     other_folder, other_emote, offset_pair,
                     other_offset, other_flip, nonint_pre,
                     looping_sfx, screenshake, frame_screenshake,
                     frame_realization, frame_sfx,
                     additive, effect, blipname, slide] + ulta_pair_extras

        # Testimony commands are not available in narrator mode
        if narration != "-" and AOProtocol.testimony_cmd_re.match(msg):
            self.client.send_ooc("Testimony commands can't be used in narrator mode.")
            return

        if not self.client.incall:
            if msg == '///':
                if self.client in self.client.area.owners and not self.client.area.is_recording and len(self.client.area.recorded_messages) != 0:
                    for statements in self.client.area.recorded_messages:
                        if statements.id == 0:
                            statement = statements
                    # Sign first so clients wait for it before the line
                    if self.client.can_wtce:
                        self.client.area.send_command('RT', 'testimony2')
                    self.client.area.send_command('MS', *statement.args)
                    self.client.area.statement = 0
            elif msg.startswith('//'):
                if self.client in self.client.area.owners and not self.client.area.is_recording:
                    self.client.area.is_recording = True
                    self.client.area.recorded_messages.clear()
                    self.client.area.statement = 0
                    statement = Statement(send_args)
                    statement.args[4] = msg[2:]
                    statement.args[14] = 0  # the title is white unless it has color symbols
                    self._ulta_flag_title(statement.args)
                    self.client.area.recorded_messages.append(statement)
                    self.client.send_ooc('Recording testimony!')
                    if self.client.can_wtce:
                        self.client.area.send_command('RT', 'testimony1')
            if msg == '/end':
                if self.client in self.client.area.owners and self.client.area.is_recording:
                    self.client.area.is_recording = False
                    self.client.area.statement += 1
                    statement = Statement(send_args)
                    statement.id = self.client.area.statement
                    self.client.area.statement = 0
                    self.client.area.recorded_messages.append(statement)
                    self.client.send_ooc('No longer recording testimony.')
            if msg.startswith('+'):
                #Commenting for clarity -- Cave
                if self.client in self.client.area.owners and self.client.area.is_recording:
                    if self.client.area.statement >= 30:
                        return self.client.send_ooc('You\'re trying to add too many statements.')
                    #Increase Global Statement Number
                    self.client.area.statement += 1
                    #Make object with message arguments
                    statement = Statement(send_args)
                    #Remove the beginning command of the message
                    statement.args[4] = msg[1:]
                    #Id equal to global statement Number
                    statement.id = self.client.area.statement
                    #Add statement to recorded message list
                    self.client.area.recorded_messages.append(statement)
                    self.client.send_ooc('Statement added!')
                elif self.client in self.client.area.owners and not self.client.area.is_recording and len(self.client.area.recorded_messages) != 0:
                    if self.client.area.statement >= 30:
                        return self.client.send_ooc('You\'re trying to add too many statements.')
                    oldstatement = self.client.area.statement
                    #This will move to another statement
                    self.client.area.statement += 1
                    statement = Statement(send_args)
                    statement.args[4] = msg[1:]
                    statement.args[14] = 1
                    self._ulta_flag_statement(statement.args)
                    statement.id = self.client.area.statement
                    #Since there may be statements before, we update everything after (including the old one) to be +1.
                    for s in self.client.area.recorded_messages:
                        if s.id >= statement.id:
                            s.id += 1
                    #NOW we add the statement.
                    self.client.area.recorded_messages.append(statement)
                    self.client.send_ooc(f'Substatement added after statement {oldstatement}!')
            if msg.startswith('<and>'):
                if self.client in self.client.area.owners and not self.client.area.is_recording and len(self.client.area.recorded_messages) != 0:
                    amend = None
                    #Find statement to Ammend
                    index = 0
                    for s in range(0, len(self.client.area.recorded_messages)):
                        if self.client.area.recorded_messages[s].id == self.client.area.statement:
                            amend = self.client.area.recorded_messages[s]
                            index = s
                    #If the statement exists (Which it should, this is just bug checking ig)... ammend.
                    if amend != None:
                        #Get it by the index found in the array!
                        newamend = self.client.area.recorded_messages[index] = Statement(send_args)
                        newamend.id = self.client.area.statement
                        newamend.args[4] = msg[5:]
                        newamend.args[14] = 1
                        self._ulta_flag_statement(newamend.args)
                        self.client.send_ooc(f'Statement {newamend.id} amended.')
            playback = False
            fastforward = False
            if msg == '>' or msg == '>>':
                if len(self.client.area.recorded_messages) != 0 and not self.client.area.is_recording:
                    self.client.area.statement += 1
                    if self.client.area.statement >= len(self.client.area.recorded_messages):
                        self.client.area.statement = 1
                        self.client.area.broadcast_ooc(f'{self.client.char_name} reached end, looping back to first statement.')
                    else:
                        self.client.area.broadcast_ooc(f'Testimony advanced by {self.client.char_name}.')
                    for s in self.client.area.recorded_messages:
                        if s.id == self.client.area.statement:
                            statement = s
                            break
                    playback = True
                    if msg == '>>':
                        fastforward = True
            elif msg.startswith('>'):
                if len(self.client.area.recorded_messages) != 0 and not self.client.area.is_recording:
                    if msg.startswith('>>'):
                        msg = msg[2:]
                        fastforward = True
                    else:
                        msg = msg[1:]
                    try:
                        statementno = int(msg)
                    except:
                        self.client.send_ooc('That is not a valid statement number.')
                        return
                    for s in self.client.area.recorded_messages:
                        if s.id == statementno:
                            statement = s
                            self.client.area.statement = statementno
                            playback = True
                            self.client.area.broadcast_ooc(f'{self.client.char_name} skipped to statement {self.client.area.statement}.')
                            break
                    if not playback:
                        self.client.send_ooc('No statement with that number found.')
                        return
            if msg == '<' or msg == '<<':
                if len(self.client.area.recorded_messages) != 0 and not self.client.area.is_recording:
                    self.client.area.statement += -1
                    if self.client.area.statement < 1:
                        self.client.area.statement = 1
                        self.client.send_ooc('At first statement, no previous statement available.')
                        for s in self.client.area.recorded_messages:
                            if s.id == self.client.area.statement:
                                statement = s
                                break
                        playback = True
                        if msg == '<<':
                            fastforward = True
                    else:
                        for s in self.client.area.recorded_messages:
                            if s.id == self.client.area.statement:
                                statement = s
                                playback = True
                                if msg == '<<':
                                    fastforward = True
                                break
                        self.client.area.broadcast_ooc(f'{self.client.char_name} went to the previous statement of the testimony.')
            if msg == '=' or msg == '==':
                if len(self.client.area.recorded_messages) != 0 and not self.client.area.is_recording:
                    if self.client.area.statement <= 0:
                        self.client.area.statement = 1
                    for s in self.client.area.recorded_messages:
                        if s.id == self.client.area.statement:
                            statement = s
                            break
                        playback = True
                        if msg == '==':
                            fastforward = True
                    self.client.area.broadcast_ooc(f'{self.client.char_name} repeated the current statement.')

            if playback:
                last = len(self.client.area.recorded_messages) - 1
                if not self.client.area.statement < 1 and not self.client.area.statement == last:
                    statement.prepce()
                if fastforward:
                    nargs = statement.args[4]
                    statement.args[4] = '}}}'
                    statement.args[4] += nargs
                self._ulta_flag_statement(statement.args)
                self.client.area.send_command('MS', *statement.args)
                if fastforward:
                    nargs = statement.args[4]
                    statement.args[4] = nargs[3:]

            if not msg == '///' or not self.client in self.client.area.owners or len(self.client.area.recorded_messages) == 0:
                if not playback:
                    if not self.client.visible:
                        if  '/' in send_args[2]:
                            send_args[3] = '../../../background/AADetentionCenter/defensedesk'
                        else:
                            send_args[3] = '../../background/AADetentionCenter/defensedesk'

                    self.client.area.ulta_scene_note_message(
                        self.client.char_id,
                        (tool_token if is_fx else ''),
                        charfx)
                    self.client.area.send_command('MS', *send_args)
                    self.server.area_manager.send_remote_command(target_area, 'MS', *send_args)
                    self.client.area.send_owner_command('MS', *owner_args)
                    self.client.area.set_next_msg_delay(len(msg))
                    self.client.area.last_speaker = self.client
                    if msg != '' and msg != ' ':
                            database.log_ic(self.client, self.client.area, showname, msg)
        else:
            self.client.call.send_owner_command('MS', *owner_args)
            self.client.call.set_next_msg_delay(len(msg))
            self.client.call.last_speaker = self.client
            if msg != '' and msg != ' ':
                database.log_ic(self.client, self.client.area, showname, msg)

    def net_cmd_ct(self, args):
        """OOC Message
        
        CT#<name:string>#<message:string>#%

        """
        if not self.client.is_checked:
            return

        if not self.validate_net_cmd(args, ArgType.STR, ArgType.STR):
            return
            
        if not self.client.is_wlisted:
            if args[1].startswith("/whitelist") or args[1].startswith("/wl"):
                pass
            else:
                self.client.send_ooc("You cannot send OOC messages without being whitelisted.")
                return

        if self.client.is_ooc_muted and not self.client.is_mod:  # Checks to see if the client has been muted by a mod
            self.client.send_ooc('You are muted by a moderator.')
        
        if self.client.char_id == -1:  #Checks if the user is a spectator
            self.client.send_ooc("Spectators can't use OOC chat.")
            return

        if self.client.name != args[0] and self.client.fake_name != args[0]:
            if self.client.is_valid_name(args[0]):
                self.client.name = args[0]
                self.client.fake_name = args[0]
            else:
                self.client.fake_name = args[0]

        if self.client.name == '':
            self.client.send_ooc(
                'You must insert a name with at least one letter')
            return

        if len(self.client.name) > 30:
            self.client.send_ooc(
                'Your OOC name is too long! Limit it to 30 characters.')
            return
        for c in self.client.name:
            if unicodedata.category(c) == 'Cf':
                self.client.send_ooc(
                    'You cannot use format characters in your name!')
                return

        if self.client.name.startswith(self.server.config['hostname']) or self.client.name.startswith('<dollar>G') or self.client.name.startswith('<dollar>M'):
            self.client.send_ooc('That name is reserved!')
            return

        if args[1].startswith(' /'):
            self.client.send_ooc(
                'Your message was not sent for safety reasons: you left a space before that slash.'
            )
            return

        if args[1].startswith('.'):
            self.client.send_ooc(
                'Your message was not sent for safety reasons: you left a dot before that message.'
            )
            return

        if len(args[1]) > 300:
            self.client.send_ooc(
                'That message is too long!.'
            )
            return

        if not args[1].startswith('/') and self.client.ooc_delay != None:
            if self.client.ooc_delay > time.perf_counter():
                self.client.send_ooc('You are trying to send messages too fast!')
                return

        if self.client.afk:
            self.client.server.client_manager.toggle_afk(self.client)
        if self.client.afktime:
            self.client.afktime.cancel()
        if self.server.config['afk_delay'] > 0:
            self.client.afktime = asyncio.get_event_loop().call_later(self.client.server.config['afk_delay'], lambda: self.client.server.client_manager.toggle_afk(self.client))

        if args[1].startswith('/'):
            spl = args[1][1:].split(' ', 1)
            cmd = spl[0].lower()
            arg = ''
            if len(spl) == 2:
                arg = spl[1][:256]
            try:
                called_function = f'ooc_cmd_{cmd}'
                if cmd == 'help' and arg != '':
                    self.client.send_ooc(commands.help(f'ooc_cmd_{arg}'))
                else:
                    getattr(commands, called_function)(self.client, arg)
            except AttributeError as e:
                print('Attribute error with ' + called_function)
                print(e)
                self.client.send_ooc('Invalid command.')
            except (ClientError, AreaError, ArgumentError, ServerError) as ex:
                self.client.send_ooc(ex)
            except Exception as ex:
                self.client.send_ooc('An internal error occurred. Please check the server log.')
                logger.exception('Exception while running a command')
            finally:
                self.server.ulta_refresh_directors()
        else:
            args[1] = self.dezalgo(args[1])
            if self.client.shaken:
                args[1] = self.client.shake_message(args[1])
            if self.client.disemvowel:
                args[1] = self.client.disemvowel_message(args[1])
            self.client.ooc_delay = (time.perf_counter() + self.server.config['ooc_delay'])
            self.client.area.send_command('CT', self.client.name, args[1])
            self.client.area.send_owner_command('CT', '[' + self.client.area.abbreviation + ']' + self.client.name, args[1])
            database.log_room('ooc', self.client, self.client.area, message=args[1])

    def net_cmd_mc(self, args):
        """Play music.
        
        MC#<song_name:int>#<???:int>#%

        """
        if not self.client.is_checked:
            return
        if not self.client.is_wlisted:
            self.client.send_ooc('You must be whitelisted from discord!')
            return
        try:
            area = self.server.area_manager.get_area_by_name(args[0], self.client)
            self.client.change_area(area)
        except AreaError:
            try:
                area = self.client.area.get_sub(args[0])
                self.client.change_area(area)
            except AreaError:
                try:
                    if self.client.area.sub:
                        area = self.client.area.hub.get_sub(args[0])
                        self.client.change_area(area)
                    else:
                        area = self.server.area_manager.get_area_by_name(args[0], self.client)
                        self.client.change_area(area)
                except AreaError:
                    if self.client.is_muted:  # Checks to see if the client has been muted by a mod
                        self.client.send_ooc(
                            'You are muted by a moderator.')
                        return
                    if not self.client.is_dj:
                        self.client.send_ooc(
                            "You were blockdj'd by a moderator.")
                        return
                    if self.client.area.cannot_ic_interact(self.client):
                        self.client.send_ooc("You are not on the area's invite list, and thus, you cannot change music!")
                        return
                    if not self.client.area.allowmusic and self.client not in self.client.area.owners:
                        self.client.send_ooc('The CM has disallowed music changes, ask them to change the music.')
                        return
                    if not self.validate_net_cmd(args, ArgType.STR, ArgType.INT):
                        if not self.validate_net_cmd(args, ArgType.STR, ArgType.INT, ArgType.STR_OR_EMPTY):
                            if not self.validate_net_cmd(args, ArgType.STR, ArgType.INT, ArgType.STR_OR_EMPTY, ArgType.INT):
                                if not self.validate_net_cmd(args, ArgType.STR, ArgType.INT, ArgType.STR_OR_EMPTY, ArgType.INT, ArgType.INT):
                                    return
                    if args[1] != self.client.char_id:
                        return
                    if self.client.change_music_cd():
                        self.client.send_ooc(
                            'You changed song too many times. Please try again after {} seconds.'
                            .format(int(self.client.change_music_cd())))
                        return
                    try:
                        if args[0] == "~stop.mp3":
                            name, length, mod, custom = args[0], 0, -1, False
                        else:
                            name, length, mod, custom = self.server.get_song_data(args[0], self.client.area)
                        if not mod == -1:
                            if not self.client.is_mod:
                                self.client.send_host_message("This song is reserved for moderators.")
                                return
                        if self.client.area.jukebox:
                            showname = ''
                            if len(args) > 2:
                                showname = args[2]
                                if len(
                                        showname
                                ) > 0 and not self.client.area.showname_changes_allowed:
                                    self.client.send_ooc(
                                        "Showname changes are forbidden in this area!")
                                    return
                            self.client.area.add_jukebox_vote(self.client, name,
                                                              length, showname)
                            database.log_room('jukebox.vote', self.client, self.client.area, message=name)
                        else:
                            if len(args) > 2:
                                showname = args[2]
                                if len(
                                        showname
                                ) > 0 and not self.client.area.showname_changes_allowed:
                                    self.client.send_ooc(
                                        "Showname changes are forbidden in this area!")
                                    return
                            # Effects info
                            effects = 0
                            if custom:
                                nname = name
                                name = 'custom/'
                                name += nname
                            if len(args) > 3:
                                effects = int(args[3])
                                self.client.area.play_music_shownamed(
                                    name, self.client.char_id, showname, length, effects)
                                self.client.area.add_music_playing_shownamed(
                                    self.client, showname, name)
                            else:
                                self.client.area.play_music(name, self.client.char_id,
                                                            length)
                                self.client.area.add_music_playing(self.client, name)
                            database.log_room('music', self.client, self.client.area, message=name)
                        if self.client.afk:
                            self.client.server.client_manager.toggle_afk(self.client)
                        if self.client.afktime:
                            self.client.afktime.cancel()
                        if self.server.config['afk_delay'] > 0:
                            self.client.afktime = asyncio.get_event_loop().call_later(self.client.server.config['afk_delay'], lambda: self.client.server.client_manager.toggle_afk(self.client))
                    except ServerError:
                        return
                except ClientError as ex:
                    self.client.send_ooc(ex)
            except ClientError as ex:
                self.client.send_ooc(ex)
        except ClientError as ex:
            self.client.send_ooc(ex)

    def net_cmd_rt(self, args):
        """Plays the Testimony/CE animation.
        
        RT#<type:string>#%

        """
        if not self.client.is_checked:
            return
        if not self.client.is_wlisted:
            self.client.send_ooc('You must be whitelisted from discord!')
            return
        if not self.client.area.shouts_allowed:
            self.client.send_ooc(
                "You cannot use the testimony buttons here!")
            return
        if self.client.is_muted:  # Checks to see if the client has been muted by a mod
            self.client.send_ooc('You are muted by a moderator.')
            return
        if not self.client.can_wtce:
            self.client.send_ooc(
                'You were blocked from using judge signs by a moderator.')
            return
        if self.client.area.cannot_ic_interact(self.client):
            self.client.send_ooc(
                "You are not on the area's invite list, and thus, you cannot use the WTCE buttons!"
            )
            return
        if not self.validate_net_cmd(
                args, ArgType.STR) and not self.validate_net_cmd(
                    args, ArgType.STR, ArgType.INT):
            return
        if args[0] == 'testimony1':
            sign = 'WT'
        elif args[0] == 'testimony2':
            sign = 'CE'
        elif args[0] == 'judgeruling':
            sign = 'JR'
        else:
            return
        if self.client.wtce_mute():
            self.client.send_ooc(
                'You used witness testimony/cross examination signs too many times. Please try again after {} seconds.'
                .format(int(self.client.wtce_mute())))
            return
        if len(args) == 1:
            self.client.area.send_command('RT', args[0])
        elif len(args) == 2:
            self.client.area.send_command('RT', args[0], args[1])
        self.client.area.add_to_judgelog(self.client, f'used {sign}')
        database.log_room('wtce', self.client, self.client.area, message=sign)

    def net_cmd_setcase(self, args):
        """ Sets the casing preferences of the given client.

        SETCASE#<cases:string>#<will_cm:int>#<will_def:int>#<will_pro:int>#<will_judge:int>#<will_jury:int>#<will_steno:int>#<will_witness:int>#%

        Note: Though all but the first arguments are ints, they technically behave as bools of 0 and 1 value.

        """
        self.client.casing_cases = args[0]
        self.client.casing_cm = args[1] == "1"
        self.client.casing_def = args[2] == "1"
        self.client.casing_pro = args[3] == "1"
        self.client.casing_jud = args[4] == "1"
        self.client.casing_jur = args[5] == "1"
        self.client.casing_steno = args[6] == "1"

    def net_cmd_casea(self, args):
        """Announces a case with a title, and specific set of people to look for.
        
        CASEA#<casetitle:string>#<need_cm:int>#<need_def:int>#<need_pro:int>#<need_judge:int>#<need_jury:int>#<need_steno:int>#%
        
        Note: Though all but the first arguments are ints, they technically behave as bools of 0 and 1 value.

        """
        if not self.client.is_checked:
            return
        if not self.client.is_wlisted:
            self.client.send_ooc('You must be whitelisted from discord!')
            return
        if self.client in self.client.area.owners or self.client.area.evidence_mod == 'FFA':
            if not self.client.can_call_case():
                raise ClientError('Please wait 60 seconds between case announcements!')

            if not args[1] == "1" and not args[2] == "1" and not args[3] == "1" and not args[4] == "1" and not args[5] == "1":
                raise ArgumentError('You should probably announce the case to at least one person.')
            msg = '=== Case Announcement ===\r\n{} [{}] is hosting {}, looking for '.format(self.client.char_name,
                                                                                            self.client.id, args[0])

            lookingfor = []

            if args[1] == "1":
                lookingfor.append("defence")
            if args[2] == "1":
                lookingfor.append("prosecutor")
            if args[3] == "1":
                lookingfor.append("judge")
            if args[4] == "1":
                lookingfor.append("juror")
            if args[5] == "1":
                lookingfor.append("stenographer")

            msg = msg + ', '.join(lookingfor) + '.\r\n=================='

            self.client.server.send_all_cmd_pred('CASEA', msg, args[1], args[2], args[3], args[4], args[5], '1')

            self.client.set_case_call_delay()

            log_data = {k: v for k, v in \
                zip(('message', 'def', 'pro', 'jud', 'jur', 'steno','wit'), args)}
            database.log_room('case', self.client, self.client.area, message=log_data)
        else:
            self.client.send_ooc(
                'You cannot announce a case in an area where you are not a CM!'
            )

    def net_cmd_hp(self, args):
        """Sets the penalty bar.
        
        HP#<type:int>#<new_value:int>#%

        """
        if not self.client.is_checked:
            return
        if not self.client.is_wlisted:
            self.client.send_ooc('You must be whitelisted from discord!')
            return
        if self.client.is_muted:  # Checks to see if the client has been muted by a mod
            self.client.send_ooc('You are muted by a moderator.')
            return
        if self.client.area.cannot_ic_interact(self.client):
            self.client.send_ooc(
                "You are not on the area's invite list, and thus, you cannot change the Confidence bars!"
            )
            return
        if not self.validate_net_cmd(args, ArgType.INT, ArgType.INT):
            return
        try:
            self.client.area.change_hp(args[0], args[1])
            self.client.area.add_to_judgelog(self.client,
                                             'changed the penalties')
            database.log_room('hp', self.client, self.client.area)
        except AreaError:
            return

    def net_cmd_pe(self, args):
        """Adds a piece of evidence.
        
        PE#<name: string>#<description: string>#<image: string>#%

        :param args: 

        """
        if not self.client.is_checked:
            return
        if not self.client.is_wlisted:
            self.client.send_ooc('You must be whitelisted from discord!')
            return
        elif len(args) < 3:
            return
        # evi = Evidence(args[0], args[1], args[2], self.client.pos)
        self.client.area.evi_list.add_evidence(self.client, args[0], args[1],
                                               args[2], 'all')
        database.log_room('evidence.add', self.client, self.client.area)
        self.client.area.broadcast_evidence_list()

    def net_cmd_de(self, args):
        """Deletes a piece of evidence.
        
        DE#<id: int>#%

        """
        if not self.client.is_checked:
            return
        if not self.client.is_wlisted:
            self.client.send_ooc('You must be whitelisted from discord!')
            return
        evi_real = self._evi_from_arg(args)
        if evi_real is None:
            return
        self.client.area.evi_list.del_evidence(self.client, evi_real)
        database.log_room('evidence.del', self.client, self.client.area)
        self.client.area.broadcast_evidence_list()

    def _evi_number(self, number):
        """Server evidence number for the number a client sent (0 if it is not in its list)."""
        if 0 < number < len(self.client.evi_list):
            return self.client.evi_list[number]
        return 0

    def _evi_from_arg(self, args):
        """Same for DE/EE packets; None when the argument is not usable."""
        try:
            number = int(args[0])
        except (ValueError, IndexError):
            return None
        if 0 <= number < len(self.client.evi_list):
            return self.client.evi_list[number]
        return None

    def net_cmd_ee(self, args):
        """Edits a piece of evidence.
        
        EE#<id: int>#<name: string>#<description: string>#<image: string>#%

        """
        if not self.client.is_checked:
            return
        if not self.client.is_wlisted:
            self.client.send_ooc('You must be whitelisted from discord!')
            return
        elif len(args) < 4:
            return

        evi = (args[1], args[2], args[3], 'all')

        evi_real = self._evi_from_arg(args)
        if evi_real is None:
            return
        self.client.area.evi_list.edit_evidence(self.client, evi_real, evi)
        database.log_room('evidence.edit', self.client, self.client.area)
        self.client.area.broadcast_evidence_list()

    def net_cmd_zz(self, args):
        """Sent on mod call.

        """
        from server.webhooks import Webhooks
        if not self.client.is_checked:
            return
        if not self.client.is_wlisted:
            self.client.send_ooc('You must be whitelisted from discord!')
            return
        if self.client.is_muted:  # Checks to see if the client has been muted by a mod
            self.client.send_ooc('You are muted by a moderator.')
            return

        if self.client.char_id == -1:
            self.client.send_ooc(
                "You cannot call a moderator while spectating.")
            return

        if not self.client.can_call_mod():
            self.client.send_ooc(
                "You must wait 30 seconds between mod calls.")
            return

        current_time = strftime("%H:%M", localtime())
        w = Webhooks(self.server)
        if len(args) < 1:
            self.server.send_all_cmd_pred(
                'ZZ',
                '[{}] {} ({}) in [{}]{} without reason (not using 2.6?)'.format(
                    current_time, self.client.char_name,
                    self.client.ip, self.client.area.abbreviation, self.client.area.name),
                pred=lambda c: c.is_mod)
            self.client.set_mod_call_delay()
            database.log_room('modcall', self.client, self.client.area)
            w.modcall(char=self.client.char_name, ipid=self.client.ip, area=self.client.area)
        else:
            self.server.send_all_cmd_pred(
                'ZZ',
                '[{}] {} ({}) in [{}]{} with reason: {}'.format(
                    current_time, self.client.char_name,
                    self.client.ip, self.client.area.abbreviation, self.client.area.name,
                    args[0][:100]),
                pred=lambda c: c.is_mod)
            self.client.set_mod_call_delay()
            database.log_room('modcall', self.client, self.client.area, message=args[0])
            w.modcall(char=self.client.char_name, ipid=self.client.ip, area=self.client.area, reason=args[0][:100])

    def net_cmd_opKICK(self, args):
        """
        Unused; kick a user from the client UI.

        """
        self.net_cmd_ct(['opkick', '/kick {}'.format(args[0])])

    def net_cmd_opBAN(self, args):
        """
        Unused; ban a user from the client UI.

        """
        self.net_cmd_ct(['opban', '/ban {}'.format(args[0])])

    net_cmd_dispatcher = {
        'HI': net_cmd_hi,  # handshake
        'ID': net_cmd_id,  # client version
        'ULTA': net_cmd_ulta,  # ULTA client extension handshake
        'FB': net_cmd_fb,  # ULTA flashback start/end
        'CH': net_cmd_ch,  # keepalive
        'askchaa': net_cmd_askchaa,     # ask for list lengths
        'askchar2': net_cmd_askchar2,  # ask for list of characters
        'AN': net_cmd_an,  # character list
        'AE': net_cmd_ae,  # evidence list
        'AM': net_cmd_am,  # music list
        'RC': net_cmd_rc,  # AO2 character list
        'RM': net_cmd_rm,  # AO2 music list
        'RD': net_cmd_rd,  # AO2 done request, charscheck etc.
        'CC': net_cmd_cc,  # select character
        'MS': net_cmd_ms,  # IC message
        'CT': net_cmd_ct,  # OOC message
        'MC': net_cmd_mc,  # play song
        'RT': net_cmd_rt,  # WT/CE buttons
        'SETCASE':
        net_cmd_setcase,  # set case-announcement preferences for user
        'CASEA': net_cmd_casea,     # announce a case
        'HP': net_cmd_hp,  # penalties
        'PE': net_cmd_pe,  # add evidence
        'DE': net_cmd_de,  # delete evidence
        'EE': net_cmd_ee,  # edit evidence
        'ZZ': net_cmd_zz,  # call mod button
        'opKICK': net_cmd_opKICK,  # /kick with guard on
        'opBAN': net_cmd_opBAN,     # /ban with guard on
    }
