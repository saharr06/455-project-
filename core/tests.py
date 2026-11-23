"""Round-trip and boundary tests for supported audio steganography."""
import io
import wave
from django.test import SimpleTestCase
from . import stego

class AudioStegoTests(SimpleTestCase):
    def setUp(self):
        buffer = io.BytesIO()
        with wave.open(buffer, 'wb') as audio:
            audio.setnchannels(1)
            audio.setsampwidth(2)
            audio.setframerate(8000)
            audio.writeframes(b'\x00\x00' * 16000)
        self.wav = buffer.getvalue()

    def test_plain_message_round_trip(self):
        encoded, _ = stego.wav_encode(self.wav, stego.pack('hello 🌍'))
        self.assertEqual(stego.unpack(stego.wav_decode(encoded)), 'hello 🌍')

    def test_encrypted_message_and_wrong_password(self):
        encoded, _ = stego.wav_encode(self.wav, stego.pack('secret', 'pass'))
        payload = stego.wav_decode(encoded)
        self.assertEqual(stego.unpack(payload, 'pass'), 'secret')
        with self.assertRaises(ValueError):
            stego.unpack(payload, 'wrong')

    def test_capacity_rejection(self):
        with self.assertRaises(ValueError):
            stego.wav_encode(self.wav, b'a' * 10000)


from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from .models import MediaItem

class InventoryTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username='inventory_test', password='test123')
        self.client.force_login(self.user)

    def test_direct_upload_is_saved(self):
        upload = SimpleUploadedFile('recording.wav', b'RIFFdemo', content_type='audio/wav')
        response = self.client.post('/library/upload/', {'file': upload})
        self.assertRedirects(response, '/library/')
        self.assertTrue(MediaItem.objects.filter(owner=self.user, name='recording.wav', carrier='audio').exists())

    def test_unsupported_upload_is_rejected(self):
        upload = SimpleUploadedFile('notes.txt', b'text')
        self.client.post('/library/upload/', {'file': upload})
        self.assertFalse(MediaItem.objects.filter(owner=self.user).exists())

class FileStegoTests(SimpleTestCase):
    def setUp(self):
        b=io.BytesIO()
        with wave.open(b,'wb') as w:
            w.setnchannels(1);w.setsampwidth(2);w.setframerate(8000);w.writeframes(b'\x00\x00'*16000)
        self.wav=b.getvalue()

    def test_file_round_trip(self):
        content=b'\x89PNG\r\n\x1a\n'+bytes(range(128))
        encoded,_=stego.wav_encode(self.wav,stego.pack_file(content,'photo.png'))
        self.assertEqual(stego.unpack_content(stego.wav_decode(encoded)),('file','photo.png',content))

    def test_encrypted_file_round_trip(self):
        encoded,_=stego.wav_encode(self.wav,stego.pack_file(b'pdfbytes','notes.pdf','secret'))
        payload=stego.wav_decode(encoded)
        self.assertEqual(stego.unpack_content(payload,'secret'),('file','notes.pdf',b'pdfbytes'))
        with self.assertRaises(ValueError):stego.unpack_content(payload,'wrong')
