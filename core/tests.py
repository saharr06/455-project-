"""
Automated tests for the steganography application.

Tests cover:
    - Plain text embedding and extraction
    - Password-based encryption and decryption
    - Incorrect password rejection
    - Carrier capacity validation
    - Inventory upload and validation
    - Secret file embedding and extraction
"""

import io
import wave

from django.test import SimpleTestCase, TestCase
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile

from . import stego
from .models import MediaItem



# 1. AUDIO STEGANOGRAPHY TESTS


class AudioStegoTests(SimpleTestCase):
    """
    Test text embedding and extraction using WAV audio.
    """

    def setUp(self):
        """
        Generate a sample WAV file before each test.
        """

        buffer = io.BytesIO()

        with wave.open(buffer, 'wb') as audio:

            # Create mono audio with one channel.
            audio.setnchannels(1)

            # Use 16-bit audio samples (2 bytes per sample).
            audio.setsampwidth(2)

            # Set the sampling rate to 8000 Hz.
            audio.setframerate(8000)

            # Generate 16000 silent audio samples.
            audio.writeframes(b'\x00\x00' * 16000)

        self.wav = buffer.getvalue()

    def test_plain_message_round_trip(self):
        """
        Verify that an unencrypted message can be hidden
        and recovered without losing information.
        """

        message = 'hello 🌍'

        # Prepare the secret message.
        payload = stego.pack(message)

        # Embed the message inside the audio.
        encoded, _ = stego.wav_encode(self.wav, payload)

        # Extract and unpack the hidden message.
        recovered_payload = stego.wav_decode(encoded)
        recovered_message = stego.unpack(recovered_payload)

        # Verify that the recovered message matches the original.
        self.assertEqual(recovered_message, message)

    def test_encrypted_message_and_wrong_password(self):
        """
        Verify successful decryption with the correct password
        and rejection of an incorrect password.
        """

        message = 'secret'
        password = 'pass'

        # Encrypt and embed the secret message.
        payload = stego.pack(message, password)
        encoded, _ = stego.wav_encode(self.wav, payload)

        # Extract the encrypted payload.
        recovered_payload = stego.wav_decode(encoded)

        # Verify successful decryption with the correct password.
        self.assertEqual(
            stego.unpack(recovered_payload, password),
            message
        )

        # Verify that an incorrect password raises an error.
        with self.assertRaises(ValueError):
            stego.unpack(recovered_payload, 'wrong')

    def test_capacity_rejection(self):
        """
        Verify that a payload exceeding the audio capacity
        cannot be embedded.
        """

        # Generate a payload larger than the carrier capacity.
        oversized_payload = b'a' * 10000

        # Encoding must raise a ValueError.
        with self.assertRaises(ValueError):
            stego.wav_encode(self.wav, oversized_payload)



# 2. INVENTORY MANAGEMENT TESTS


class InventoryTests(TestCase):
    """
    Test file uploads and inventory validation.
    """

    def setUp(self):
        """
        Create and authenticate a temporary test user.
        """

        self.user = get_user_model().objects.create_user(
            username='inventory_test',
            password='test123'
        )

        # Authenticate the test user without using the login page.
        self.client.force_login(self.user)

    def test_direct_upload_is_saved(self):
        """
        Verify that a file with a supported extension
        is saved in the user's inventory.
        """

        # Create a simulated WAV upload.
        upload = SimpleUploadedFile(
            'recording.wav',
            b'RIFFdemo',
            content_type='audio/wav'
        )

        # Submit the file to the inventory upload endpoint.
        response = self.client.post(
            '/library/upload/',
            {'file': upload}
        )

        # Verify that the user is redirected to the inventory.
        self.assertRedirects(response, '/library/')

        # Check that the file record exists in the database.
        self.assertTrue(
            MediaItem.objects.filter(
                owner=self.user,
                name='recording.wav',
                carrier='audio'
            ).exists()
        )

    def test_unsupported_upload_is_rejected(self):
        """
        Verify that unsupported carrier file types are rejected.
        """

        # Create a file with an unsupported extension.
        upload = SimpleUploadedFile(
            'notes.txt',
            b'text'
        )

        # Attempt to upload the unsupported file.
        self.client.post(
            '/library/upload/',
            {'file': upload}
        )

        # Verify that no inventory record was created.
        self.assertFalse(
            MediaItem.objects.filter(
                owner=self.user
            ).exists()
        )



# 3. SECRET FILE STEGANOGRAPHY TESTS


class FileStegoTests(SimpleTestCase):
    """
    Test embedding and extracting binary files using WAV audio.
    """

    def setUp(self):
        """
        Generate a sample WAV carrier before each test.
        """

        buffer = io.BytesIO()

        with wave.open(buffer, 'wb') as audio:

            audio.setnchannels(1)
            audio.setsampwidth(2)
            audio.setframerate(8000)

            # Generate two seconds of silent audio.
            audio.writeframes(b'\x00\x00' * 16000)

        self.wav = buffer.getvalue()

    def test_file_round_trip(self):
        """
        Verify that binary file content and its original
        filename are preserved after embedding and extraction.
        """

        # Generate sample binary data with a PNG signature.
        content = b'\x89PNG\r\n\x1a\n' + bytes(range(128))
        filename = 'photo.png'

        # Prepare the secret file without encryption.
        payload = stego.pack_file(content, filename)

        # Embed the file inside the audio carrier.
        encoded, _ = stego.wav_encode(self.wav, payload)

        # Extract and unpack the hidden file.
        recovered_payload = stego.wav_decode(encoded)
        recovered_content = stego.unpack_content(
            recovered_payload
        )

        # Verify the content type, filename, and original bytes.
        self.assertEqual(
            recovered_content,
            ('file', filename, content)
        )

    def test_encrypted_file_round_trip(self):
        """
        Verify that an encrypted binary file can be recovered
        using the correct password.
        """

        content = b'pdfbytes'
        filename = 'notes.pdf'
        password = 'secret'

        # Prepare and encrypt the secret file.
        payload = stego.pack_file(
            content,
            filename,
            password
        )

        # Embed the encrypted file inside the audio.
        encoded, _ = stego.wav_encode(self.wav, payload)

        # Extract the encrypted payload.
        recovered_payload = stego.wav_decode(encoded)

        # Verify successful file recovery.
        self.assertEqual(
            stego.unpack_content(recovered_payload, password),
            ('file', filename, content)
        )

        # Verify that an incorrect password prevents recovery.
        with self.assertRaises(ValueError):
            stego.unpack_content(recovered_payload, 'wrong')