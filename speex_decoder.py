import os
import wave
from collections import defaultdict

# Import the pySpeex pyd
import speex

SAMPLE_RATE = 16000     # speex.pyx hardcodes WB mode
CHANNELS = 1
SAMPWIDTH = 2           # int16

# Decoder instances keyed by (player_id, channel_id)
_DECODERS = {}

# PCM buffers keyed by (map_id, player_id, channel_id)
_PCM = defaultdict(bytearray)


def _ensure_decoder(player_id: int, channel_id: int):
    key = (player_id, channel_id)
    dec = _DECODERS.get(key)
    if dec is None:
        # raw=1 -> decode returns a bytes object of int16 samples
        dec = speex.new(quality=8, raw=1, debug=0)
        _DECODERS[key] = dec
    return dec


def decode_speex_bundle(player_id: int, channel_id: int, speex_data: bytes) -> bytes:
    """
    Decode a 'bundle' of Speex WB frames.

    speex.pyx decode() expects the input to be composed of one or more blocks:
      [uint16_le block_size][block_bytes...][uint16_le block_size][block_bytes...]...

    Returns:
      PCM as little-endian int16 bytes at 16 kHz mono.
    """
    if not speex_data:
        return b""

    dec = _ensure_decoder(player_id, channel_id)

    # With raw=1, this returns already-clamped PCM int16 bytes (per your patched pyd)
    pcm_bytes = dec.decode(speex_data)
    return pcm_bytes or b""


def append_pcm(map_id: int, player_id: int, channel_id: int, pcm: bytes):
    """
    Accumulate PCM bytes for later WAV flush.
    """
    if not pcm:
        return
    _PCM[(map_id, player_id, channel_id)].extend(pcm)


def flush_map(map_id: int, out_dir: str):
    """
    Write WAV files for all (player,channel) buffers belonging to map_id,
    then clear them from memory.
    """
    os.makedirs(out_dir, exist_ok=True)

    to_flush = [k for k in _PCM.keys() if k[0] == map_id]
    for (m, player_id, channel_id) in to_flush:
        pcm_bytes = bytes(_PCM[(m, player_id, channel_id)])
        if not pcm_bytes:
            del _PCM[(m, player_id, channel_id)]
            continue

        wav_path = os.path.join(
            out_dir,
            f"map{m:04d}_player{player_id:04d}_ch{channel_id:02d}.wav"
        )

        with wave.open(wav_path, "wb") as wf:
            wf.setnchannels(CHANNELS)
            wf.setsampwidth(SAMPWIDTH)
            wf.setframerate(SAMPLE_RATE)
            wf.writeframes(pcm_bytes)

        del _PCM[(m, player_id, channel_id)]


def cleanup():
    """
    Clear decoder state + PCM buffers.
    """
    _DECODERS.clear()
    _PCM.clear()
