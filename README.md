# Stegonography — Audio & Video Django Website

A local educational web application for hiding and extracting text messages inside **PCM WAV audio** and **lossless FFV1 AVI video**.

## Run on Windows PowerShell

```powershell
cd stegovault
py -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
```

Open http://127.0.0.1:8000/ and select **Create account**.

## Features
- Sign-up, sign-in and sign-out. A password is required for accounts but there are **no password strength or complexity rules**; confirmation still must match.
- PCM WAV LSB steganography, first-frame video LSB steganography, FFV1 AVI output.
- Optional AES-256-GCM message encryption, scrypt password derivation, password-protected extraction.
- Inventory with audio sample, original/encoded files, downloads and deletion.
- Capacity check, technical tutorial, responsive lavender-and-purple interface.

## Technical details and limitations
- WAV: embeds one bit per PCM sample, into its lowest byte; input and output must be uncompressed WAV.
- Video: embeds in the first frame, exports lossless FFV1 AVI. OpenCV/FFmpeg FFV1 support is required. Video audio tracks are **not preserved**.
- The encoded media must not be compressed or edited after embedding.
- Uploads are limited to 50 MB; payload envelopes to 2 MB. Video output may be much larger than the input.
- Accounts are protected by Django password hashing; optional **message** passwords are independent of account passwords.
- This is an educational local app, not production hardened. See Django deployment checklist before hosting publicly.

## Testing

```powershell
python manage.py test core
```




### Inventory behavior
Every newly registered account receives both `sample_tone.wav` and `sample_video.avi` in its inventory. The inventory page also has an independent upload form. Files uploaded during Hide Message or Extract Message are automatically stored as originals in the signed-in user's inventory; encoded results are stored separately. Files selected from the existing inventory are not duplicated. Existing accounts created with an earlier release can upload the included sample files manually from the `samples/` directory. The original dark charcoal and lime accent colors have been restored.


