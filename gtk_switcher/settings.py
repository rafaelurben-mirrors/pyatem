# Copyright 2021 - 2022, Martijn Braam and the OpenAtem contributors
# SPDX-License-Identifier: GPL-3.0-only
import json

import gi

from pyatem.command import MultiviewInputCommand, VideoModeCommand, AutoInputVideoModeCommand, SaveStartupStateCommand, \
    ClearStartupStateCommand, UsbAudioFunctionCommand
from pyatem.field import InputPropertiesField, UsbAudioFunctionField

gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, GLib, GObject, Gio, Gdk

gi.require_version('Handy', '1')
from gi.repository import Handy


class SettingsWindow:
    def __init__(self, parent, application):
        self.application = application
        self.settings = Gio.Settings.new('nl.brixit.Switcher')
        self.model_changing = False
        self.config = {}

        builder = Gtk.Builder()
        builder.set_translation_domain("openswitcher")
        builder.add_from_resource('/nl/brixit/switcher/ui/settings.glade')
        builder.connect_signals(self)
        css = Gio.resources_lookup_data("/nl/brixit/switcher/ui/style.css", 0)

        self.provider = Gtk.CssProvider()
        self.provider.load_from_data(css.get_data())

        self.window = builder.get_object("window")
        self.window.set_application(self.application)

        self.launch_reconnect = builder.get_object("launch_reconnect")
        self.launch_ask = builder.get_object("launch_ask")
        self._ignore_prop_changed = False

        map_launch_reconnect = MapDict({
            True: 'Reconnect to last',
            False: 'List connections',
        })
        map_launch_ask = MapDict({
            False: 'Reconnect to last',
            True: 'List connections',
        })
        self.bind_with_mapping("launchmode", self.launch_reconnect, "active", Gio.SettingsBindFlags.DEFAULT,
                               map_launch_reconnect.lookup_reverse, map_launch_reconnect.__getitem__)
        self.bind_with_mapping("launchmode", self.launch_ask, "active", Gio.SettingsBindFlags.DEFAULT,
                               map_launch_ask.lookup_reverse, map_launch_ask.__getitem__)

        self.apply_css(self.window, self.provider)
        self.window.set_transient_for(parent)
        self.window.set_modal(True)
        self.window.show_all()

    def bind_with_mapping(self, key, widget, prop, flags, key_to_prop, prop_to_key):
        """
        Recreate g_settings_bind_with_mapping from scratch.
        This method was shamelessly stolen from Robert Park's
        gottengeography who shamelessly stolen it from John Stowers'
        gnome-tweak-tool on May 14, 2012.
        """
        self._ignore_key_changed = False

        def key_changed(settings, key):
            if self._ignore_key_changed:
                return
            self._ignore_prop_changed = True
            widget.set_property(prop, key_to_prop(self.settings[key]))
            self._ignore_prop_changed = False

        def prop_changed(widget, param):
            if self._ignore_prop_changed:
                return
            self._ignore_key_changed = True
            self.settings[key] = prop_to_key(widget.get_property(prop))
            self._ignore_key_changed = False

        if not (flags & (Gio.SettingsBindFlags.SET | Gio.SettingsBindFlags.GET)):  # ie Gio.SettingsBindFlags.DEFAULT
            flags |= Gio.SettingsBindFlags.SET | Gio.SettingsBindFlags.GET

        if flags & Gio.SettingsBindFlags.GET:
            key_changed(self.settings, key)
            if not (flags & Gio.SettingsBindFlags.GET_NO_CHANGES):
                self.settings.connect('changed::' + key, key_changed)
        if flags & Gio.SettingsBindFlags.SET:
            widget.connect('notify::' + prop, prop_changed)
        if not (flags & Gio.SettingsBindFlags.NO_SENSITIVITY):
            self.settings.bind_writable(key, widget, "sensitive", False)

    def apply_css(self, widget, provider):
        Gtk.StyleContext.add_provider(widget.get_style_context(),
                                      provider,
                                      Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

        if isinstance(widget, Gtk.Container):
            widget.forall(self.apply_css, provider)


class MapDict(dict):
    def lookup_reverse(self, value):
        for key in self.keys():
            if self[key] == value:
                return key
