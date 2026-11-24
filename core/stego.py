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



# 7. VIDEO STEGANOGRAPHY - ENCODING AND DECODING


def video_process(source_path, output_path, payload=None):
    """
    Hide or extract secret information using the first video frame.

    If a payload is provided, the function performs encoding.
    If no payload is provided, the function performs decoding.

    The output video uses the lossless FFV1 codec to preserve
    the modified least significant bits.
    """

    import cv2

    # Open the source video using OpenCV.
    cap = cv2.VideoCapture(str(source_path))

    if not cap.isOpened():
        raise ValueError(
            'Cannot read video. Try an AVI or MP4 input.'
        )

    # Read the original video properties.
    fps = cap.get(cv2.CAP_PROP_FPS) or 24

    width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))

    # Validate the video dimensions.
    if width < 1 or height < 1:

        cap.release()

        raise ValueError('Invalid video dimensions.')

  
    # VIDEO DECODING
    

    if payload is None:

        # Read the first frame containing the hidden information.
        ok, frame = cap.read()

        cap.release()

        if not ok:
            raise ValueError('Video contains no frames.')

        # Flatten the frame into a one-dimensional array
        # of Blue, Green, and Red color values.
        pixel_values = frame.reshape(-1)

        # Extract the hidden information from the pixel LSBs.
        return extract(pixel_values)

   
    # VIDEO ENCODING
  

    # Read the first frame of the video.
    ok, first = cap.read()

    if not ok:

        cap.release()

        raise ValueError('Video contains no frames.')

    # Flatten the first frame into a one-dimensional array.
    # Each pixel contains three color channels: B, G, and R.
    pixel_values = first.reshape(-1)

    # Hide the secret information in the pixel color values.
    insert(pixel_values, payload)

    # Create the output video using the lossless FFV1 codec.
    # Lossless encoding preserves the modified pixel values.
    writer = cv2.VideoWriter(
        str(output_path),
        cv2.VideoWriter_fourcc(*'FFV1'),
        fps,
        (width, height)
    )

    if not writer.isOpened():

        cap.release()

        raise ValueError(
            'FFV1 video encoder unavailable in OpenCV.'
        )

    try:

        # Write the modified first frame.
        writer.write(first)

        # Read and write the remaining frames without
        # embedding any additional secret information.
        while True:

            ok, frame = cap.read()

            if not ok:
                break

            writer.write(frame)

    finally:

        # Release the video resources.
        writer.release()
        cap.release()

    # Each pixel contains three color values.
    # Each color value can store one secret bit.
    # Divide by eight to convert bits into bytes.
    # Subtract four bytes for the payload length header.
    return max(0, width * height * 3 // 8 - 4)


# 8. CARRIER CAPACITY CALCULATION


def capacity(raw, carrier):
    """
    Estimate the available payload capacity of a WAV carrier.
    Video capacity is calculated during video processing.
    """

    if carrier == 'audio':

        with wave.open(io.BytesIO(raw), 'rb') as wf:

            # Divide the number of audio frames by eight
            # and subtract the four-byte payload length header.
            return max(0, wf.getnframes() // 8 - 4)

    return None