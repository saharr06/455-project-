import io
import wave
import tempfile
from pathlib import Path

import cv2
import numpy as np
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, SimpleTestCase, override_settings
from . import stego
from .models import MediaItem


class WebsiteTests(TestCase):
    def setUp(self):
        self.media = tempfile.TemporaryDirectory()
        self.addCleanup(self.media.cleanup)
        settings = override_settings(MEDIA_ROOT=self.media.name)
        settings.enable()
        self.addCleanup(settings.disable)
        self.user = get_user_model().objects.create_user(
            username='website_test', password='TestPassword123!')
        self.client.force_login(self.user)

    def test_dashboard_requires_login(self):
        self.client.logout()
        self.assertRedirects(self.client.get('/dashboard/'),
                             '/login/?next=/dashboard/', fetch_redirect_response=False)

    def test_login_correct_password(self):
        self.client.logout()
        response = self.client.post('/login/', {
            'username': 'website_test', 'password': 'TestPassword123!'})
        self.assertEqual(response.status_code, 302)
        self.assertIn('_auth_user_id', self.client.session)

    def test_login_wrong_password(self):
        self.client.logout()
        self.client.post('/login/', {
            'username': 'website_test', 'password': 'incorrect'})
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_audio_website_round_trip(self):
        buffer = io.BytesIO()
        with wave.open(buffer, 'wb') as audio:
            audio.setnchannels(1)
            audio.setsampwidth(2)
            audio.setframerate(8000)
            audio.writeframes(b'\x00\x00' * 16000)
        message = 'Website integration test'
        response = self.client.post('/encode/', {
            'carrier': 'audio', 'secret_mode': 'text', 'message': message,
            'password': 'TestSecret123!',
            'file': SimpleUploadedFile('test.wav', buffer.getvalue())})
        self.assertTemplateUsed(response, 'core/result.html')
        item = MediaItem.objects.get(owner=self.user, kind='encoded')
        response = self.client.post('/decode/', {
            'carrier': 'audio', 'item_id': item.pk, 'password': 'TestSecret123!'})
        self.assertEqual(response.context['secret'], message)
        response = self.client.post('/decode/', {
            'carrier': 'audio', 'item_id': item.pk, 'password': 'wrong'})
        self.assertIsNone(response.context.get('secret'))

    def test_inventory_privacy_and_delete(self):
        self.client.post('/library/upload/', {
            'file': SimpleUploadedFile('test.wav', b'RIFFdemo')})
        item = MediaItem.objects.get(owner=self.user, name='test.wav')
        other = get_user_model().objects.create_user(username='other')
        self.client.force_login(other)
        self.assertEqual(self.client.get(f'/library/{item.pk}/download/').status_code, 404)
        self.assertEqual(self.client.post(f'/library/{item.pk}/delete/').status_code, 404)
        self.client.force_login(self.user)
        response = self.client.get(f'/library/{item.pk}/download/')
        self.assertEqual(response.status_code, 200)
        response.close()
        self.client.post(f'/library/{item.pk}/delete/')
        self.assertFalse(MediaItem.objects.filter(pk=item.pk).exists())


class VideoTests(SimpleTestCase):
    def test_video_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'original.avi'
            output = Path(directory) / 'encoded.avi'
            writer = cv2.VideoWriter(str(source), cv2.VideoWriter_fourcc(*'FFV1'), 10, (64, 64))
            if not writer.isOpened():
                writer.release()
                self.skipTest('FFV1 codec unavailable')
            try:
                for _ in range(10):
                    writer.write(np.full((64, 64, 3), 120, dtype=np.uint8))
            finally:
                writer.release()
            message = 'Video test'
            stego.video_process(source, output, stego.pack(message))
            self.assertEqual(stego.unpack(stego.video_process(output, None)), message)
