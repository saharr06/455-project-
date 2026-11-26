"""
Audio and Video Steganography using LSB.

Supported formats:
    - Uncompressed PCM WAV audio
    - Video with lossless FFV1 AVI output

Optional encryption:
    - AES-256-GCM
    - Scrypt password-based key derivation

Payload structure:
    4-byte payload length + encrypted or unencrypted content

Lossy compression should be avoided because it may destroy
the hidden information stored in the least significant bits.
"""

import io
import os
import json
import struct
import wave
import subprocess
import tempfile
from pathlib import Path
import subprocess
import tempfile
from pathlib import Path
import numpy as np

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


# Maximum allowed payload size in bytes (2 MB).
MAX_PAYLOAD = 2_000_000



# 1. ENCRYPTION AND DATA PREPARATION


def protect(data, password=''):
    """
    Encrypt the secret data if a password is provided.
    Otherwise, return the data without encryption.
    """

    if password:

        # Generate a random 16-byte salt for key derivation.
        salt = os.urandom(16)

        # Generate a random 12-byte nonce for AES-GCM.
        nonce = os.urandom(12)

        # Derive a 256-bit encryption key from the password.
        key = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1
        ).derive(password.encode())

        # Encrypt the data and generate an authentication tag.
        encrypted_data = AESGCM(key).encrypt(
            nonce,
            data,
            None
        )

        # SV1E indicates that the payload is encrypted.
        # Store the salt and nonce for later decryption.
        return b'SV1E' + salt + nonce + encrypted_data

    # SV1P indicates that the payload is not encrypted.
    return b'SV1P' + data


def pack(message, password=''):
    """
    Convert a text message into bytes and optionally encrypt it.
    """

    # Convert the text into UTF-8 bytes.
    data = message.encode('utf-8')

    if not data:
        raise ValueError('Please enter a message.')

    # SF2T identifies the hidden content as text.
    return protect(b'SF2T' + data, password)


def pack_file(data, filename, password=''):
    """
    Prepare a secret file while preserving its original filename.
    The file can optionally be encrypted.
    """

    if not data:
        raise ValueError('Choose a nonempty secret file.')

    # Keep only the filename, without its directory path.
    name = Path(filename).name

    # Store the filename as JSON metadata.
    header = json.dumps(
        {'name': name},
        ensure_ascii=False
    ).encode('utf-8')

    if len(header) > 4096:
        raise ValueError('Filename is too long.')

    # SF2F identifies the hidden content as a file.
    # Store the header length using two bytes.
    payload = (
        b'SF2F'
        + struct.pack('>H', len(header))
        + header
        + data
    )

    return protect(payload, password)



# 2. DECRYPTION AND CONTENT RECOVERY


def unpack_content(blob, password=''):
    """
    Recover the original hidden text or file.

    Returns:
        Content type, original filename, and content bytes.
    """

    # Check whether the hidden content is unencrypted.
    if blob.startswith(b'SV1P'):

        # Remove the four-byte identification marker.
        data = blob[4:]

    # Check whether the hidden content is encrypted.
    elif blob.startswith(b'SV1E'):

        if not password:
            raise ValueError('This message requires a password.')

        # Recover the salt, nonce, and encrypted data.
        salt = blob[4:20]
        nonce = blob[20:32]
        cipher = blob[32:]

        # Derive the encryption key using the entered password
        # and the original salt.
        key = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1
        ).derive(password.encode())

        try:
            # Decrypt the data and verify its authentication tag.
            data = AESGCM(key).decrypt(nonce, cipher, None)

        except Exception:
            raise ValueError(
                'Incorrect password or damaged hidden message.'
            ) from None

    else:
        raise ValueError(
            'No supported hidden content was found.'
        )

    # Recover a hidden file.
    if data.startswith(b'SF2F'):

        if len(data) < 6:
            raise ValueError('Damaged hidden file header.')

        # Read the two-byte filename header length.
        size = struct.unpack('>H', data[4:6])[0]

        # Validate the header size.
        if size > 4096 or len(data) < 6 + size:
            raise ValueError('Damaged hidden file header.')

        try:
            # Recover the original filename from the JSON header.
            header = json.loads(
                data[6:6 + size].decode('utf-8')
            )

            name = Path(header['name']).name

        except Exception:
            raise ValueError(
                'Damaged hidden file header.'
            ) from None

        # Return the filename and original file bytes.
        return 'file', name, data[6 + size:]

    # Recover a hidden text message.
    if data.startswith(b'SF2T'):
        return 'text', '', data[4:]

    # Support older text payloads.
    return 'text', '', data


def unpack(blob, password=''):
    """
    Recover a hidden text message and convert it back to a string.
    """

    kind, _, data = unpack_content(blob, password)

    if kind != 'text':
        raise ValueError('Hidden content is a file, not text.')

    return data.decode('utf-8')



# 3. LSB EMBEDDING ALGORITHM


def insert(bits, payload):
    """
    Hide the payload inside the least significant bits
    of audio sample bytes or video pixel color values.
    """

    # Check the maximum allowed payload size.
    if len(payload) > MAX_PAYLOAD:
        raise ValueError('Message is too large.')

    # Add a four-byte header containing the payload length.
    # The decoder uses this header to determine how much to read.
    data = struct.pack('>I', len(payload)) + payload

    # Convert the payload bytes into individual binary bits.
    bitstream = np.unpackbits(
        np.frombuffer(data, dtype=np.uint8)
    )

    # Check whether the carrier has enough available space.
    if bitstream.size > bits.size:

        available_capacity = max(0, (bits.size // 8) - 4)

        raise ValueError(
            f'Carrier too small. Capacity: '
            f'{available_capacity} bytes.'
        )

    # LSB embedding:
    # 254 = 11111110 in binary.
    # AND with 254 clears the least significant bit.
    # OR with the secret bit inserts the hidden information.
    bits[:bitstream.size] = (
        bits[:bitstream.size] & 254
    ) | bitstream

    return bits



# 4. LSB EXTRACTION ALGORITHM


def extract(bits):
    """
    Recover the hidden payload from the least significant bits
    of audio sample bytes or video pixel color values.
    """

    # At least 32 carrier values are required for the length header.
    if bits.size < 32:
        raise ValueError('Carrier is too small.')

    # Read the first 32 least significant bits.
    # AND with 1 extracts only the last bit of each value.
    length_bits = bits[:32] & 1

    # Convert the 32 bits back into four bytes.
    length_bytes = np.packbits(length_bits).tobytes()

    # Recover the original payload length.
    length = struct.unpack('>I', length_bytes)[0]

    # Validate the recovered payload length.
    if (
        not 4 <= length <= MAX_PAYLOAD
        or (length + 4) * 8 > bits.size
    ):
        raise ValueError(
            'No supported hidden message was found.'
        )

    # Extract the hidden bits after the 32-bit length header.
    payload_bits = bits[32:(length + 4) * 8] & 1

    # Convert the extracted bits back into the original bytes.
    return np.packbits(payload_bits).tobytes()



# 5. AUDIO STEGANOGRAPHY - ENCODING


def wav_encode(raw, payload):
    """
    Hide secret information inside an uncompressed PCM WAV file.
    """

    # Open the WAV file and read its parameters and audio frames.
    with wave.open(io.BytesIO(raw), 'rb') as wf:

        params = wf.getparams()
        frames = wf.readframes(wf.getnframes())

    # Only uncompressed PCM audio is supported.
    if (
        params.comptype != 'NONE'
        or params.sampwidth not in (1, 2, 3, 4)
    ):
        raise ValueError(
            'Only uncompressed PCM WAV is supported.'
        )

    # Interpret the audio bytes as an array of unsigned integers.
    # Each value contains eight bits and ranges from 0 to 255.
    arr = np.frombuffer(frames, dtype=np.uint8).copy()

    # Select the least significant byte of each audio sample.
    # The remaining bytes of each sample are preserved.
    indices = np.arange(
        0,
        len(arr),
        params.sampwidth
    )

    selected = arr[indices].copy()

    # Apply the LSB embedding algorithm.
    insert(selected, payload)

    # Replace the original bytes with the modified bytes.
    arr[indices] = selected

    # Create an in-memory output WAV file.
    out = io.BytesIO()

    with wave.open(out, 'wb') as wf:

        # Preserve the original audio parameters.
        wf.setparams(params)

        # Write the modified audio samples.
        wf.writeframes(arr.tobytes())

    # Calculate the available payload capacity in bytes.
    available_capacity = len(indices) // 8 - 4

    return out.getvalue(), available_capacity



# 6. AUDIO STEGANOGRAPHY - DECODING


def wav_decode(raw):
    """
    Extract hidden information from an encoded WAV file.
    """

    # Read the audio sample width and audio frames.
    with wave.open(io.BytesIO(raw), 'rb') as wf:

        width = wf.getsampwidth()
        frames = wf.readframes(wf.getnframes())

    # Convert the audio bytes into a NumPy array.
    arr = np.frombuffer(frames, dtype=np.uint8)

    # Select the same byte positions used during encoding.
    selected = arr[::width]

    # Recover the hidden payload using LSB extraction.
    return extract(selected)

def preserve_video_audio(source_path, output_path):
    """Restore the original audio without changing encoded frames."""

    output_path = Path(output_path)

    with tempfile.TemporaryDirectory(
        dir=output_path.parent
    ) as directory:

        merged = Path(directory) / 'merged.avi'

        command = [
            'ffmpeg',
            '-y',
            '-i', str(output_path),
            '-i', str(source_path),
            '-map', '0:v:0',
            '-map', '1:a:0?',
            '-c:v', 'copy',
            '-c:a', 'pcm_s16le',
            str(merged)
        ]

        try:
            subprocess.run(
                command,
                check=True,
                capture_output=True,
                timeout=120
            )

        except FileNotFoundError:
            raise ValueError('FFmpeg is not installed.')

        except subprocess.TimeoutExpired:
            raise ValueError('Audio restoration timed out.')

        except subprocess.CalledProcessError:
            raise ValueError('Cannot restore video audio.')

        merged.replace(output_path)

# 7. VIDEO STEGANOGRAPHY - ENCODING AND DECODING


def video_process(source_path, output_path, payload=None):
    import cv2

    cap = cv2.VideoCapture(str(source_path))
    writer = None

    try:
        if not cap.isOpened():
            raise ValueError('Cannot read video.')

        # DECODING MODE
        if payload is None:
            chunks = []
            collected = 0
            target = 32
            length = None

            while True:
                ok, frame = cap.read()

                if not ok:
                    break

                flat = frame.reshape(-1)
                pos = 0

                while pos < flat.size and collected < target:

                    take = min(
                        flat.size - pos,
                        target - collected
                    )

                    # Extract least significant bits
                    chunks.append(
                        flat[pos:pos + take] & 1
                    )

                    collected += take
                    pos += take

                    # Read the 4-byte payload length
                    if length is None and collected == 32:
                        header = np.packbits(
                            np.concatenate(chunks)
                        ).tobytes()

                        length = struct.unpack('>I', header)[0]

                        if not 4 <= length <= MAX_PAYLOAD:
                            raise ValueError(
                                'No supported hidden message found.'
                            )

                        target = (length + 4) * 8

                # Return the complete extracted payload
                if length is not None and collected == target:
                    return np.packbits(
                        np.concatenate(chunks)[32:]
                    ).tobytes()

            raise ValueError('Incomplete hidden message.')

        # ENCODING MODE
        if len(payload) > MAX_PAYLOAD:
            raise ValueError('Message is too large.')

        fps = cap.get(cv2.CAP_PROP_FPS) or 24
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))

        if width < 1 or height < 1:
            raise ValueError('Invalid video dimensions.')

        if width % 2 or height % 2:
            raise ValueError('Video dimensions must be even.')

        # Add the payload length and convert to bits
        data = struct.pack('>I', len(payload)) + payload

        stream = np.unpackbits(
            np.frombuffer(data, dtype=np.uint8)
        )

        writer = cv2.VideoWriter(
            str(output_path),
            cv2.VideoWriter_fourcc(*'FFV1'),
            fps,
            (width, height)
        )

        if not writer.isOpened():
            raise ValueError('FFV1 encoder unavailable.')

        offset = 0
        total = 0

        while True:
            ok, frame = cap.read()

            if not ok:
                break

            if frame.shape != (height, width, 3):
                raise ValueError('Unexpected frame dimensions.')

            flat = frame.reshape(-1)
            total += flat.size

            # Number of bits to hide in this frame
            take = min(flat.size, stream.size - offset)

            if take > 0:

                # Clear LSBs and insert secret bits
                flat[:take] = (
                    flat[:take] & 254
                ) | stream[offset:offset + take]

                offset += take

            # Write every frame to the output video
            writer.write(frame)

        if offset < stream.size:
         raise ValueError('Video capacity is too small.')

# Finish writing the encoded video
        writer.release()
        writer = None

# Close the original video
        cap.release()

# Restore the original audio track
        preserve_video_audio(source_path, output_path)

        return min(MAX_PAYLOAD,max(0, total // 8 - 4)
)

    finally:
        cap.release()

        if writer is not None:
            writer.release()

# 8. CARRIER CAPACITY CALCULATION
def video_capacity(source_path):
    import cv2

    cap = cv2.VideoCapture(str(source_path))
    total = 0

    try:
        if not cap.isOpened():
            raise ValueError('Cannot read video.')

        while True:
            ok, frame = cap.read()

            if not ok:
                break

            total += frame.size

    finally:
        cap.release()

    if total == 0:
        raise ValueError('Video contains no frames.')

    return min(
        MAX_PAYLOAD,
        max(0, total // 8 - 4)
    )

def capacity(raw, carrier):

    if carrier == 'audio':

        with wave.open(io.BytesIO(raw), 'rb') as wf:

            total_samples = (
                wf.getnframes() * wf.getnchannels()
            )

            return min(
                MAX_PAYLOAD,
                max(0, total_samples // 8 - 4)
            )

    return None

def convert_audio_to_wav(raw, filename):
    """Convert supported audio input to PCM WAV."""

    with tempfile.TemporaryDirectory() as directory:

        source = Path(directory) / Path(filename).name
        output = Path(directory) / 'converted.wav'

        source.write_bytes(raw)

        command = [
            'ffmpeg',
            '-y',
            '-i', str(source),
            '-vn',
            '-c:a', 'pcm_s16le',
            str(output)
        ]

        try:
            subprocess.run(
                command,
                check=True,
                capture_output=True,
                timeout=120
            )

        except FileNotFoundError:
            raise ValueError('FFmpeg is not installed.')

        except subprocess.TimeoutExpired:
            raise ValueError('Audio conversion timed out.')

        except subprocess.CalledProcessError:
            raise ValueError('Cannot convert this audio file.')

        return output.read_bytes()
# 9. TECHNICAL ANALYSIS

import math
import base64


def calculate_metrics(total, changed, absolute, squared,
                      maximum, peak, signal_power):

    if total == 0:
        raise ValueError('No media values to compare.')

    mse = squared / total
    mae = absolute / total

    psnr = (
        'Infinity'
        if mse == 0
        else round(10 * math.log10(peak ** 2 / mse), 4)
    )

    if squared == 0:
        snr = 'Infinity'
    elif signal_power == 0:
        snr = 'Undefined for silent original'
    else:
        snr = round(
            10 * math.log10(signal_power / squared), 4
        )

    return {
        'mse': round(mse, 10),
        'mae': round(mae, 10),
        'psnr': psnr,
        'snr': snr,
        'total': total,
        'changed': changed,
        'unchanged': total - changed,
        'change_percent': round(changed / total * 100, 8),
        'similarity': round((total - changed) / total * 100, 8),
        'max_error': maximum,
        'normalized_error': round(mae / peak * 100, 10),
        'capacity': min(
            MAX_PAYLOAD,
            max(0, total // 8 - 4)
        )
    }


def frame_to_base64(frame):

    import cv2

    success, buffer = cv2.imencode('.png', frame)

    if not success:
        raise ValueError('Cannot generate frame preview.')

    return base64.b64encode(
        buffer.tobytes()
    ).decode('utf-8')


def compare_videos(original_path, encoded_path):

    import cv2

    original = cv2.VideoCapture(str(original_path))
    encoded = cv2.VideoCapture(str(encoded_path))

    total = 0
    changed = 0
    absolute = 0.0
    squared = 0.0
    maximum = 0
    signal_power = 0.0
    frames = 0

    previews = {}

    try:

        if not original.isOpened() or not encoded.isOpened():
            raise ValueError('Cannot open the selected videos.')

        while True:

            ok1, frame1 = original.read()
            ok2, frame2 = encoded.read()

            if ok1 != ok2:
                raise ValueError(
                    'The videos have different frame counts.'
                )

            if not ok1:
                break

            if frame1.shape != frame2.shape:
                raise ValueError(
                    'The video dimensions must match.'
                )

            # Convert before subtraction to avoid overflow.
            a = frame1.astype(np.float64)
            b = frame2.astype(np.float64)

            difference = np.abs(a - b)

            total += difference.size
            changed += int(np.count_nonzero(difference))

            absolute += float(np.sum(difference))
            squared += float(np.sum(difference ** 2))

            signal_power += float(np.sum(a ** 2))

            maximum = max(
                maximum,
                int(np.max(difference))
            )

            frames += 1

            # Preview the first frame.
            if frames == 1:

                # Amplify differences to make them visible.
                difference_image = np.clip(
                    difference * 255, 0, 255
                ).astype(np.uint8)

                previews = {
                    'original_image': frame_to_base64(frame1),
                    'encoded_image': frame_to_base64(frame2),
                    'difference_image': frame_to_base64(
                        difference_image
                    ),
                    'width': frame1.shape[1],
                    'height': frame1.shape[0]
                }

        result = calculate_metrics(
            total,
            changed,
            absolute,
            squared,
            maximum,
            255,
            signal_power
        )

        result.update(previews)
        result['frames'] = frames
        result['unit'] = 'Pixel channel values'

        return result

    finally:

        original.release()
        encoded.release()


def read_pcm_samples(raw):

    with wave.open(io.BytesIO(raw), 'rb') as wf:

        params = wf.getparams()
        data = wf.readframes(wf.getnframes())

    width = params.sampwidth

    if width == 1:

        samples = (
            np.frombuffer(data, dtype=np.uint8)
            .astype(np.int32) - 128
        )

    elif width == 2:

        samples = np.frombuffer(data, dtype='<i2')

    elif width == 3:

        values = np.frombuffer(
            data, dtype=np.uint8
        ).reshape(-1, 3).astype(np.int32)

        samples = (
            values[:, 0]
            | (values[:, 1] << 8)
            | (values[:, 2] << 16)
        )

        samples = (
            samples ^ 0x800000
        ) - 0x800000

    elif width == 4:

        samples = np.frombuffer(data, dtype='<i4')

    else:

        raise ValueError('Unsupported PCM sample width.')

    return params, samples


def compare_audio(original_raw, encoded_raw):

    p1, samples1 = read_pcm_samples(original_raw)
    p2, samples2 = read_pcm_samples(encoded_raw)

    if (
        p1.nchannels != p2.nchannels
        or p1.sampwidth != p2.sampwidth
        or p1.framerate != p2.framerate
        or samples1.size != samples2.size
    ):

        raise ValueError(
            'Audio parameters must match.'
        )

    if samples1.size == 0:
        raise ValueError('Audio contains no samples.')

    a = samples1.astype(np.float64)
    b = samples2.astype(np.float64)

    difference = np.abs(a - b)

    peak = 2 ** (p1.sampwidth * 8 - 1)

    result = calculate_metrics(
        difference.size,
        int(np.count_nonzero(difference)),
        float(np.sum(difference)),
        float(np.sum(difference ** 2)),
        int(np.max(difference)),
        peak,
        float(np.sum(a ** 2))
    )

    result['samples'] = int(samples1.size)
    result['sample_rate'] = p1.framerate
    result['channels'] = p1.nchannels
    result['bit_depth'] = p1.sampwidth * 8
    result['duration'] = round(
        p1.nframes / p1.framerate, 3
    )

    result['unit'] = 'Audio samples'

    return result
