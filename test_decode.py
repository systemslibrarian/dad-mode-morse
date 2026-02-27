#!/usr/bin/env python3
"""
test_decode.py
--------------
Round-trip test for the Morse WAV decode algorithm used in index.html.

Synthesises Morse WAV samples using the same parameters as the JS app
(44100 Hz, 700 Hz tone, 60 ms unit), then decodes them with a Python
port of the JS `decodeMorseWav` function and compares the result.

Run with:
    python3 test_decode.py
"""

import array
import math
import wave
import os
import sys

# ── Synth parameters (must match JS app) ────────────────────────────────────
SAMPLE_RATE = 44100
FREQ_HZ     = 700
UNIT_MS     = 60
VOL         = 0.35
TMP_WAV     = "/tmp/_morse_test.wav"


# ── Synthesis helpers ────────────────────────────────────────────────────────

def ms2n(ms):
    return max(1, int(SAMPLE_RATE * ms / 1000))


def make_beep(tone_ms):
    n    = ms2n(tone_ms)
    fade = max(1, int(SAMPLE_RATE * 0.006))
    s    = []
    ph   = 0.0
    inc  = 2 * math.pi * FREQ_HZ / SAMPLE_RATE
    for i in range(n):
        amp = VOL
        if i < fade:         amp *= i / fade
        if n - i - 1 < fade: amp *= (n - i - 1) / fade
        s.append(math.sin(ph) * amp)
        ph += inc
    return s


def make_silence(ms):
    return [0.0] * ms2n(ms)


def synth_morse(morse_str, unit=UNIT_MS):
    dot  = unit
    dash = unit * 3
    egap = unit       # element gap
    lgap = unit * 3   # letter gap
    wgap = unit * 7   # word gap
    pcm  = []
    for c in morse_str:
        if   c == '.': pcm += make_beep(dot);  pcm += make_silence(egap)
        elif c == '-': pcm += make_beep(dash); pcm += make_silence(egap)
        elif c == ' ': pcm += make_silence(lgap)
        elif c == '/': pcm += make_silence(wgap)
    while pcm and pcm[-1] == 0.0:
        pcm.pop()
    return pcm


def write_wav(path, samples):
    raw = array.array('h', [max(-32768, min(32767, int(v * 32767))) for v in samples])
    with wave.open(path, 'wb') as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(SAMPLE_RATE)
        wf.writeframes(raw.tobytes())


def read_wav(path):
    with wave.open(path, 'rb') as wf:
        sr  = wf.getframerate()
        raw = wf.readframes(wf.getnframes())
        ch  = wf.getnchannels()
    samps = array.array('h', raw)
    if ch == 1:
        return sr, [s / 32767 for s in samps]
    # mix all channels to mono
    mono = [sum(samps[i + c] for c in range(ch)) / (ch * 32767)
            for i in range(0, len(samps), ch)]
    return sr, mono


# ── Decode algorithm (port of JS decodeMorseWav) ────────────────────────────

def decode_morse(samples, sr=SAMPLE_RATE, frame_ms=5):
    fn      = max(1, int(sr * frame_ms / 1000))
    nf      = len(samples) // fn
    energy  = [
        math.sqrt(sum(v * v for v in samples[f * fn:(f + 1) * fn]) / fn)
        for f in range(nf)
    ]

    p95       = sorted(energy)[int(len(energy) * 0.95)]
    threshold = p95 * 0.15
    if p95 < 1e-5:
        raise ValueError("Audio appears silent — is this a Morse WAV?")

    binary = [1 if e > threshold else 0 for e in energy]

    # Run-length encode
    runs = []
    cur, cnt = binary[0], 1
    for b in binary[1:]:
        if b == cur:
            cnt += 1
        else:
            runs.append((cur, cnt * frame_ms))
            cur, cnt = b, 1
    runs.append((cur, cnt * frame_ms))

    # Strip leading/trailing silence
    while runs and runs[0][0]  == 0: runs.pop(0)
    while runs and runs[-1][0] == 0: runs.pop()
    if not runs:
        raise ValueError("No tone detected — is this a Morse WAV?")

    on_durs = sorted(r[1] for r in runs if r[0] == 1)

    # Estimate unit length using the largest relative gap between sorted durations
    # (splits dot cluster from dash cluster).  Falls back for unimodal inputs.
    raw_unit = UNIT_MS
    if on_durs:
        med        = on_durs[len(on_durs) // 2]
        max_ratio  = 1
        split_idx  = -1
        for i in range(len(on_durs) - 1):
            ratio = on_durs[i + 1] / (on_durs[i] or 1)
            if ratio > max_ratio:
                max_ratio = ratio
                split_idx = i + 1
        if max_ratio > 1.8 and split_idx > 0:
            dot_cluster = on_durs[:split_idx]
            raw_unit = round(sum(dot_cluster) / len(dot_cluster))
        elif med > 100:
            raw_unit = round(med / 3)   # unimodal long  → all dashes
        else:
            raw_unit = med              # unimodal short → all dots

    unit = max(20, raw_unit)

    morse = ""
    for val, ms in runs:
        if val == 1:
            morse += "." if ms < unit * 2 else "-"
        else:
            if   ms < unit * 2: pass          # element gap
            elif ms < unit * 5: morse += " "  # letter gap
            else:               morse += " / " # word gap

    return morse.strip()


# ── Test cases ───────────────────────────────────────────────────────────────

TESTS = [
    (".- -... -.-. -.. . ..-.",    "A B C D E F"),
    ("... --- ...",                 "SOS-like pattern"),
    (".---- ..--- ...-- ....-",    "Digits 1 2 3 4"),
    ("-----",                       "All-dashes (hex '0')"),
    (".....",                       "All-dots (hex '5')"),
    (".-",                          "Single character A"),
    (".---- ----- .---- -----",    "1 0 1 0 mixed"),
    ("--. --- --- -.. .--- ----.",  "Cipher-like mix"),
    # Test 9: extra leading + trailing silence must not affect output
    ("_SILENCE_.- -..._SILENCE_",  "Leading/trailing silence padding"),
    # Test 10: stereo WAV decodes identically to mono
    ("_STEREO_... --- ..._STEREO_", "Stereo WAV (two-channel)"),
    # Test 11: all 16 hex-Morse characters round-trip
    ("----- .---- ..--- ...-- ....- ..... -.... --... ---.. ----. .- -... -.-. -.. . ..-.",
     "All 16 hex Morse chars (0-F)"),
    # Test 12: long cipher-like payload (simulates real encrypted message Morse)
    (".---- ----- .- ..-. -.-. -.. . ...-- --... ---.. ----. -.... ..... ....- ..--- -...",
     "Long cipher-like hex payload"),
    # Test 13: rapid alternating dots and dashes
    (".- -... .- -... .- -...",    "Rapid alternating A B A B A B"),
    # Test 14: word gap (/) between groups
    ("_WORDGAP_.- -... / -.-. -.._WORDGAP_", "Word gap detection (/)"),
    # Test 15: variable speed (faster unit)
    ("_SPEED30_... --- ..._SPEED30_", "Faster unit (30 ms)"),
    # Test 16: variable speed (slower unit)
    ("_SPEED120_... --- ..._SPEED120_", "Slower unit (120 ms)"),
]


def write_wav_stereo(path, samples):
    """Write a stereo WAV (same signal on both channels)."""
    interleaved = array.array('h')
    for s in samples:
        v = max(-32768, min(32767, int(s * 32767)))
        interleaved.append(v)  # left
        interleaved.append(v)  # right
    with wave.open(path, 'wb') as wf:
        wf.setnchannels(2)
        wf.setsampwidth(2)
        wf.setframerate(SAMPLE_RATE)
        wf.writeframes(interleaved.tobytes())


def run_tests():
    all_pass = True
    for morse_in, desc in TESTS:

        # Test 9: leading/trailing silence
        if morse_in.startswith("_SILENCE_"):
            actual_morse = morse_in.replace("_SILENCE_", "").strip("_")
            padding = make_silence(500)   # 500 ms silence each side
            samples = padding + synth_morse(actual_morse) + padding
            write_wav(TMP_WAV, samples)
            sr, wav_samples = read_wav(TMP_WAV)
            decoded = decode_morse(wav_samples, sr)
            passed  = decoded == actual_morse
            if not passed:
                all_pass = False
            print(f"[{'PASS' if passed else 'FAIL'}] {desc}")
            if not passed:
                print(f"        expected : {actual_morse}")
                print(f"        got      : {decoded}")
            continue

        # Test 10: stereo WAV
        if morse_in.startswith("_STEREO_"):
            actual_morse = morse_in.replace("_STEREO_", "").strip("_")
            samples = synth_morse(actual_morse)
            write_wav_stereo(TMP_WAV, samples)
            sr, wav_samples = read_wav(TMP_WAV)
            decoded = decode_morse(wav_samples, sr)
            passed  = decoded == actual_morse
            if not passed:
                all_pass = False
            print(f"[{'PASS' if passed else 'FAIL'}] {desc}")
            if not passed:
                print(f"        expected : {actual_morse}")
                print(f"        got      : {decoded}")
            continue

        # Test 14: word gap
        if morse_in.startswith("_WORDGAP_"):
            actual_morse = morse_in.replace("_WORDGAP_", "").strip("_")
            write_wav(TMP_WAV, synth_morse(actual_morse))
            sr, wav_samples = read_wav(TMP_WAV)
            decoded = decode_morse(wav_samples, sr)
            passed  = decoded == actual_morse
            if not passed:
                all_pass = False
            print(f"[{'PASS' if passed else 'FAIL'}] {desc}")
            if not passed:
                print(f"        expected : {actual_morse}")
                print(f"        got      : {decoded}")
            continue

        # Test 15/16: variable speed
        if morse_in.startswith("_SPEED"):
            import re as _re
            m = _re.match(r"_SPEED(\d+)_(.+?)_SPEED\d+_$", morse_in)
            speed_unit = int(m.group(1))
            actual_morse = m.group(2)
            write_wav(TMP_WAV, synth_morse(actual_morse, unit=speed_unit))
            sr, wav_samples = read_wav(TMP_WAV)
            decoded = decode_morse(wav_samples, sr)
            passed  = decoded == actual_morse
            if not passed:
                all_pass = False
            print(f"[{'PASS' if passed else 'FAIL'}] {desc}")
            if not passed:
                print(f"        expected : {actual_morse}")
                print(f"        got      : {decoded}")
            continue

        # Standard round-trip
        write_wav(TMP_WAV, synth_morse(morse_in))
        sr, samples = read_wav(TMP_WAV)
        decoded = decode_morse(samples, sr)
        passed  = decoded == morse_in
        if not passed:
            all_pass = False
        print(f"[{'PASS' if passed else 'FAIL'}] {desc}")
        if not passed:
            print(f"        expected : {morse_in}")
            print(f"        got      : {decoded}")

    print()
    if all_pass:
        print("=== All tests passed ===")
    else:
        print("=== SOME TESTS FAILED ===")
        sys.exit(1)

    try:
        os.remove(TMP_WAV)
    except OSError:
        pass


if __name__ == "__main__":
    run_tests()
