"""
Django views for the Stegonography application.

Main responsibilities:
    - User registration and authentication
    - Audio and video encoding
    - Hidden content extraction
    - Personal media inventory
    - File upload, download, and deletion
    - Carrier capacity calculation
"""

import tempfile
import uuid

from pathlib import Path

from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django.core.files.base import ContentFile
from django.http import FileResponse, JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.http import require_POST

from .models import MediaItem
from . import stego


# Maximum carrier file upload size: 50 MB.
MAX_FILE = 50 * 1024 * 1024

# Supported audio and video file extensions.
EXT = {
    'audio': {'.wav'},
    'video': {'.avi', '.mp4', '.mov', '.mkv'}
}



# 1. USER AUTHENTICATION AND DASHBOARD


def seed_samples(user):
    """
    Provide each new user with personal copies of sample media.
    """

    from django.conf import settings

    samples_directory = settings.BASE_DIR / 'samples'

    for path in sorted(samples_directory.glob('*')):

        if path.suffix.lower() in {'.wav', '.avi'}:

            # Determine the carrier type from the extension.
            carrier = (
                'audio'
                if path.suffix.lower() == '.wav'
                else 'video'
            )

            save_item(
                user,
                path.read_bytes(),
                path.name,
                carrier,
                'sample'
            )


def home(request):
    """
    Redirect users according to their authentication status.
    """

    if request.user.is_authenticated:
        return redirect('dashboard')

    return redirect('login')


def signup(request):
    """
    Register a new user and automatically log them in.
    """

    form = UserCreationForm(request.POST or None)

    if request.method == 'POST' and form.is_valid():

        # Create the new user account.
        user = form.save()

        # Add starter audio and video files.
        seed_samples(user)

        # Log the user into the application.
        login(request, user)

        return redirect('dashboard')

    return render(
        request,
        'core/signup.html',
        {'form': form}
    )


@login_required
def dashboard(request):
    """
    Display the dashboard and the user's five most recent files.
    """

    recent = MediaItem.objects.filter(
        owner=request.user
    ).order_by('-created')[:5]

    return render(
        request,
        'core/dashboard.html',
        {'recent': recent}
    )



# 2. MEDIA RETRIEVAL AND STORAGE


def get_media(request, carrier, save_upload=False):
    """
    Retrieve a media file from the user's inventory
    or from a new file upload.
    """

    item_id = request.POST.get('item_id')
    uploaded = request.FILES.get('file')

    # Retrieve an existing file from the inventory.
    if item_id:

        # Ensure that the file belongs to the logged-in user.
        item = get_object_or_404(
            MediaItem,
            pk=item_id,
            owner=request.user
        )

        if item.carrier != carrier:
            raise ValueError(
                'Choose a file of the selected media type.'
            )

        with item.file.open('rb') as f:
            return f.read(), item.name

    # Ensure that a new file was uploaded.
    if not uploaded:
        raise ValueError(
            'Select an uploaded file or a file from your library.'
        )

    # Validate the file extension.
    ext = Path(uploaded.name).suffix.lower()

    if ext not in EXT[carrier]:
        raise ValueError(
            'Unsupported file extension for selected carrier.'
        )

    # Validate the file size.
    if uploaded.size > MAX_FILE:
        raise ValueError('Maximum upload size is 50 MB.')

    # Read the uploaded file as bytes.
    raw = uploaded.read()
    name = Path(uploaded.name).name

    # Optionally save the uploaded file in the inventory.
    if save_upload:
        save_item(
            request.user,
            raw,
            name,
            carrier,
            'original'
        )

    return raw, name


def save_item(user, content, name, carrier, kind):
    """
    Save a media item and its associated file in the inventory.
    """

    # Create a database object associated with the user.
    item = MediaItem(
        owner=user,
        name=name,
        carrier=carrier,
        kind=kind
    )

    # Generate a unique filename to avoid naming conflicts.
    unique_name = uuid.uuid4().hex + '_' + name

    # Save the file and its database record.
    item.file.save(
        unique_name,
        ContentFile(content),
        save=True
    )

    return item



# 3. STEGANOGRAPHY ENCODING


@login_required
def encode(request):
    """
    Hide a text message or secret file inside audio or video.

    Password-based AES encryption is optional.
    """

    if request.method == 'POST':

        try:

            # Retrieve and validate the selected carrier type.
            carrier = request.POST.get('carrier', 'audio')

            if carrier not in EXT:
                raise ValueError('Invalid carrier type.')

            # Retrieve the carrier and save new uploads.
            raw, name = get_media(
                request,
                carrier,
                save_upload=True
            )

            # Retrieve the secret content and optional password.
            secret_upload = request.FILES.get('secret_file')
            mode = request.POST.get('secret_mode', 'text')
            password = request.POST.get('password', '')

            
            # Prepare a secret file.
           

            if mode == 'file':

                if not secret_upload:
                    raise ValueError(
                        'Choose a secret file to hide.'
                    )

                # Reserve space for metadata and encryption.
                if secret_upload.size > stego.MAX_PAYLOAD - 8192:
                    raise ValueError(
                        'Secret file exceeds the 2 MB payload limit.'
                    )

                payload = stego.pack_file(
                    secret_upload.read(),
                    secret_upload.name,
                    password
                )

           
            # Prepare a secret text message.
            

            elif mode == 'text':

                payload = stego.pack(
                    request.POST.get('message', ''),
                    password
                )

            else:
                raise ValueError(
                    'Invalid hidden content type.'
                )

            
            # Audio encoding.
            

            if carrier == 'audio':

                # Apply LSB embedding to WAV audio samples.
                result, cap = stego.wav_encode(raw, payload)

                output = 'hidden_' + Path(name).stem + '.wav'

            
            # Video encoding.
            

            else:

                # OpenCV processes video using temporary files.
                with tempfile.TemporaryDirectory() as d:

                    src = Path(d) / (
                        'input' + Path(name).suffix.lower()
                    )

                    dst = Path(d) / 'encoded.avi'

                    # Save the uploaded video temporarily.
                    src.write_bytes(raw)

                    # Hide the payload in the first video frame.
                    cap = stego.video_process(
                        src,
                        dst,
                        payload
                    )

                    # Read the lossless encoded video.
                    result = dst.read_bytes()

                output = 'hidden_' + Path(name).stem + '.avi'

            # Save the encoded carrier in the user's inventory.
            item = save_item(
                request.user,
                result,
                output,
                carrier,
                'encoded'
            )

            messages.success(
                request,
                'Hidden content embedded successfully. '
                'Download the lossless output to share it.'
            )

            # Display the encoded file and capacity information.
            return render(
                request,
                'core/result.html',
                {
                    'item': item,
                    'capacity': cap,
                    'payload_size': len(payload)
                }
            )

        except Exception as exc:

            # Display processing errors to the user.
            messages.error(request, str(exc))

    # Display the encoding page and available inventory files.
    items = MediaItem.objects.filter(
        owner=request.user
    ).order_by('-created')

    return render(
        request,
        'core/encode.html',
        {'items': items}
    )



# 4. STEGANOGRAPHY DECODING


@login_required
def decode(request):
    """
    Extract hidden text or files from encoded audio or video.

    If the content is encrypted, the correct password is required.
    """

    if request.method == 'POST':

        try:

            # Retrieve and validate the carrier type.
            carrier = request.POST.get('carrier', 'audio')

            if carrier not in EXT:
                raise ValueError('Invalid carrier type.')

            raw, name = get_media(
                request,
                carrier,
                save_upload=True
            )

          
            # Audio extraction.
           

            if carrier == 'audio':

                blob = stego.wav_decode(raw)

            
            # Video extraction.
            

            else:

                with tempfile.TemporaryDirectory() as d:

                    path = Path(d) / (
                        'input' + Path(name).suffix.lower()
                    )

                    path.write_bytes(raw)

                    # No payload is passed, so video_process()
                    # operates in decoding mode.
                    blob = stego.video_process(path, None)

            # Decrypt if necessary and identify the content type.
            kind, filename, content = stego.unpack_content(
                blob,
                request.POST.get('password', '')
            )

            
            # Recover a hidden file.
            

            if kind == 'file':

                # Store the extracted file in the user's inventory.
                item = save_item(
                    request.user,
                    content,
                    filename,
                    carrier,
                    'extracted'
                )

                items = MediaItem.objects.filter(
                    owner=request.user
                ).order_by('-created')

                return render(
                    request,
                    'core/decode.html',
                    {
                        'extracted_item': item,
                        'items': items
                    }
                )

            
            # Recover a hidden text message.
          

            # Convert the recovered bytes into readable text.
            secret = content.decode('utf-8')

            items = MediaItem.objects.filter(
                owner=request.user
            ).order_by('-created')

            return render(
                request,
                'core/decode.html',
                {
                    'secret': secret,
                    'items': items
                }
            )

        except Exception as exc:

            messages.error(request, str(exc))

    # Display the decoding page.
    items = MediaItem.objects.filter(
        owner=request.user
    ).order_by('-created')

    return render(
        request,
        'core/decode.html',
        {'items': items}
    )


# 5. INVENTORY MANAGEMENT


@login_required
@require_POST
def upload_inventory(request):
    """
    Upload and save an audio or video file without encoding it.
    """

    try:

        uploaded = request.FILES.get('file')

        if not uploaded:
            raise ValueError(
                'Choose an audio or video file.'
            )

        # Identify the file extension.
        ext = Path(uploaded.name).suffix.lower()

        # Determine whether the file is audio or video.
        carrier = next(
            (
                kind
                for kind, extensions in EXT.items()
                if ext in extensions
            ),
            None
        )

        if carrier is None:
            raise ValueError(
                'Only WAV audio and AVI, MP4, MOV, '
                'or MKV video are supported.'
            )

        # Validate the uploaded file size.
        if uploaded.size > MAX_FILE:
            raise ValueError(
                'Maximum upload size is 50 MB.'
            )

        # Save the original file in the inventory.
        save_item(
            request.user,
            uploaded.read(),
            Path(uploaded.name).name,
            carrier,
            'original'
        )

        messages.success(
            request,
            'File uploaded and saved to your inventory.'
        )

    except ValueError as exc:

        messages.error(request, str(exc))

    return redirect('library')


@login_required
def library(request):
    """
    Display all media files belonging to the logged-in user.
    """

    items = MediaItem.objects.filter(
        owner=request.user
    ).order_by('-created')

    return render(
        request,
        'core/library.html',
        {'items': items}
    )


@login_required
def download(request, pk):
    """
    Allow users to download files from their own inventory.
    """

    # Verify file ownership before allowing the download.
    item = get_object_or_404(
        MediaItem,
        pk=pk,
        owner=request.user
    )

    return FileResponse(
        item.file.open('rb'),
        as_attachment=True,
        filename=item.name
    )


@login_required
@require_POST
def delete(request, pk):
    """
    Delete a file and its associated database record.
    """

    # Ensure that the file belongs to the logged-in user.
    item = get_object_or_404(
        MediaItem,
        pk=pk,
        owner=request.user
    )

    # Delete the physical file.
    item.file.delete(save=False)

    # Delete the database record.
    item.delete()

    messages.success(request, 'File deleted.')

    return redirect('library')



# 6. CARRIER CAPACITY CALCULATION


@login_required
@require_POST
def capacity_view(request):
    """
    Calculate the available payload capacity of a carrier.

    Return the result as JSON so the interface can display
    the capacity without reloading the entire page.
    """

    try:

        carrier = request.POST.get('carrier', 'audio')

        raw, _ = get_media(request, carrier)

        
        # Calculate video capacity.
       

        if carrier == 'video':

            import cv2

            with tempfile.TemporaryDirectory() as d:

                uploaded = request.FILES.get('file')

                if uploaded:

                    path = Path(d) / (
                        'input' + Path(uploaded.name).suffix
                    )

                else:

                    path = Path(d) / 'input.avi'

                path.write_bytes(raw)

                # Read the video dimensions.
                cap = cv2.VideoCapture(str(path))

                width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
                height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))

                cap.release()

                # Three color channels per pixel.
                # One hidden bit per color channel.
                # Divide by eight to obtain bytes.
                # Subtract four bytes for the length header.
                value = max(
                    0,
                    width * height * 3 // 8 - 4
                )

        # Calculate audio capacity.
        

        else:

            value = stego.capacity(raw, carrier)

        # Return capacity information to the frontend.
        return JsonResponse({
            'capacity_bytes': value,
            'note': (
                'Capacity includes encryption overhead; '
                'available message text may be smaller.'
            )
        })

    except Exception as exc:

        return JsonResponse(
            {'error': str(exc)},
            status=400
        )


# 7. INFORMATION PAGES


def tutorial(request):
    """
    Display instructions explaining how to use the application.
    """

    return render(request, 'core/tutorial.html')


def features(request):
    """
    Display the available application features.
    """

    return render(request, 'core/features.html')