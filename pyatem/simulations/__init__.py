from pyatem.field import FirmwareVersionField, ProductNameField, TopologyField, MixerEffectConfigField, \
    MediaplayerSlotsField, FairlightAudioConfigField, MultiviewerConfigField


class VirtualATEM:
    RAW_TOPOLOGY = b'\0' * 28
    RAW_FEC = b'\x00\x04\x00\x00\x01\x00\x00\x00\x00\x00\x00\x1e\x00\x00\x01\x8b\x02\x00\x00\x00\x00\x00\x00d\x00\x00\x05\xc8\x04\x00\x00\x00\x00\x00\x01\xc2\x00\x00\x1e\xe6\x08\x00\x00\x00\x00\x00\x05x\x00\x00T\xc4'

    def __init__(self):
        self.firmware_version = (2, 31)
        self.product_name = "Generic ATEM"
        self.product_model = 0

        self.me = []
        self.mediaplayer = MediaPlayer(20, 0)
        self.multiviewer = []
        self.supersource = []
        self.fairlight = None

        self.state = {}

    def initialize(self):
        pass

    def make_state(self):
        yield FirmwareVersionField.create(*self.firmware_version)
        yield ProductNameField.create(self.product_name, self.product_model)
        yield TopologyField(self.RAW_TOPOLOGY)

        for unit in self.me:
            yield unit.get_config()

        yield self.mediaplayer.get_config()

        if len(self.multiviewer) > 0:
            yield self.multiviewer[0].get_global_config()

        for unit in self.supersource:
            yield unit.get_config()

        if self.fairlight:
            yield self.fairlight.get_config()

    def __repr__(self):
        return f'<VirtualATEM {self.product_name}>'


class Extreme(VirtualATEM):
    RAW_TOPOLOGY = b'\x01\x1d\x02\x03\x00\x02\x01\x00\n\x01\x00\x01\x00\x00\x00\x01\x00\x00\x01\x00\x00\x00\x01\x01\x01\x00\x00\x00'
    RAW_FEC = b'\x00\x04\x00\x00\x01\x00\x00\x00\x00\x00\x00\x1e\x00\x00\x01\x8b\x02\x00\x00\x00\x00\x00\x00d\x00\x00\x05\xc8\x04\x00\x00\x00\x00\x00\x01\xc2\x00\x00\x1e\xe6\x08\x00\x00\x00\x00\x00\x05x\x00\x00T\xc4'

    def __init__(self):
        super().__init__()

        self.product_name = 'ATEM Mini Extreme'
        self.product_model = 0x10
        self.me.append(MixEffectUnit(1, 4))
        self.multiviewer.append(Multiviewer(16))
        self.mediaplayer = MediaPlayer(20, 0)
        self.fairlight = FairlightMixer(10, 1)
        self.supersource = SuperSource()


class MixEffectUnit:
    def __init__(self, index, keyers):
        self.index = index
        self.keyers = keyers

    def get_config(self):
        return MixerEffectConfigField.create(self.index, self.keyers)


class MediaPlayer:
    def __init__(self, still_banks, clip_banks):
        self.still_banks = still_banks
        self.clip_banks = clip_banks

    def get_config(self):
        return MediaplayerSlotsField.create(self.still_banks, self.clip_banks)


class SuperSource:
    pass


class Multiviewer:
    def __init__(self, windows):
        self.windows = windows

    def get_global_config(self):
        return MultiviewerConfigField.create(self.windows)


class FairlightMixer:
    def __init__(self, channels, monitors):
        self.channels = channels
        self.monitors = monitors

    def get_config(self):
        return FairlightAudioConfigField.create(self.channels, self.monitors)
