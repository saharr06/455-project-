import io,os,tempfile,uuid
from pathlib import Path
from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django.core.files.base import ContentFile
from django.http import FileResponse,JsonResponse,Http404, HttpResponse
from django.shortcuts import render,redirect,get_object_or_404
from django.views.decorators.http import require_POST
from .models import MediaItem
from . import stego
MAX_FILE=50*1024*1024
EXT={'audio':{'.wav'},'video':{'.avi','.mp4','.mov','.mkv'}}
def seed_samples(user):
 # Give each new user independent copies of starter media.
 from django.conf import settings
 for path in sorted((settings.BASE_DIR/'samples').glob('*')):
  if path.suffix.lower() in {'.wav', '.avi'}:
   save_item(user,path.read_bytes(),path.name,'audio' if path.suffix.lower()=='.wav' else 'video','sample')

def home(request):
 return redirect('dashboard' if request.user.is_authenticated else 'login')
def signup(request):
 form=UserCreationForm(request.POST or None)
 if request.method=='POST' and form.is_valid():
  user=form.save();seed_samples(user);login(request,user);return redirect('dashboard')
 return render(request,'core/signup.html',{'form':form})
@login_required
def dashboard(request):return render(request,'core/dashboard.html',{'recent':MediaItem.objects.filter(owner=request.user).order_by('-created')[:5]})
def get_media(request,carrier,save_upload=False):
 item_id=request.POST.get('item_id');uploaded=request.FILES.get('file')
 if item_id:
  item=get_object_or_404(MediaItem,pk=item_id,owner=request.user)
  if item.carrier!=carrier:raise ValueError('Choose a file of the selected media type.')
  with item.file.open('rb') as f:return f.read(),item.name
 if not uploaded:raise ValueError('Select an uploaded file or a file from your library.')
 ext=Path(uploaded.name).suffix.lower()
 if ext not in EXT[carrier]:raise ValueError('Unsupported file extension for selected carrier.')
 if uploaded.size>MAX_FILE:raise ValueError('Maximum upload size is 50 MB.')
 raw=uploaded.read();name=Path(uploaded.name).name
 if save_upload:save_item(request.user,raw,name,carrier,'original')
 return raw,name

def save_item(user,content,name,carrier,kind):
 item=MediaItem(owner=user,name=name,carrier=carrier,kind=kind)
 item.file.save(uuid.uuid4().hex+'_'+name,ContentFile(content),save=True)
 return item
@login_required
def encode(request):
 if request.method=='POST':
  try:
   carrier=request.POST.get('carrier','audio')
   if carrier not in EXT:raise ValueError('Invalid carrier type.')
   raw,name=get_media(request,carrier,save_upload=True)
   secret_upload=request.FILES.get('secret_file')
   mode=request.POST.get('secret_mode','text')
   if mode=='file':
    if not secret_upload:raise ValueError('Choose a secret file to hide.')
    if secret_upload.size>stego.MAX_PAYLOAD-8192:raise ValueError('Secret file exceeds the 2 MB payload limit.')
    payload=stego.pack_file(secret_upload.read(),secret_upload.name,request.POST.get('password',''))
   elif mode=='text':payload=stego.pack(request.POST.get('message',''),request.POST.get('password',''))
   else:raise ValueError('Invalid hidden content type.')
   if carrier=='audio':
    result,cap=stego.wav_encode(raw,payload)
    output='hidden_'+Path(name).stem+'.wav'
   else:
    with tempfile.TemporaryDirectory() as d:
     src=Path(d)/('input'+Path(name).suffix.lower())
     dst=Path(d)/'encoded.avi'
     src.write_bytes(raw)
     cap=stego.video_process(src,dst,payload)
     result=dst.read_bytes()
    output='hidden_'+Path(name).stem+'.avi'
   item=save_item(request.user,result,output,carrier,'encoded')
   messages.success(request,'Hidden content embedded successfully. Download the lossless output to share it.')
   return render(request,'core/result.html',{'item':item,'capacity':cap,'payload_size':len(payload)})
  except Exception as exc:messages.error(request,str(exc))
 return render(request,'core/encode.html',{'items':MediaItem.objects.filter(owner=request.user).order_by('-created')})
@login_required
def decode(request):
 if request.method=='POST':
  try:
   carrier=request.POST.get('carrier','audio')
   if carrier not in EXT:raise ValueError('Invalid carrier type.')
   raw,name=get_media(request,carrier,save_upload=True)
   if carrier=='audio':blob=stego.wav_decode(raw)
   else:
    with tempfile.TemporaryDirectory() as d:
     path=Path(d)/('input'+Path(name).suffix.lower());path.write_bytes(raw);blob=stego.video_process(path,None)
   kind,filename,content=stego.unpack_content(blob,request.POST.get('password',''))
   if kind=='file':
    # Store extracted bytes server-side; downloads require the same logged-in owner.
    item=save_item(request.user,content,filename,carrier,'extracted')
    return render(request,'core/decode.html',{'extracted_item':item,'items':MediaItem.objects.filter(owner=request.user).order_by('-created')})
   secret=content.decode('utf-8')
   return render(request,'core/decode.html',{'secret':secret,'items':MediaItem.objects.filter(owner=request.user).order_by('-created')})
  except Exception as exc:messages.error(request,str(exc))
 return render(request,'core/decode.html',{'items':MediaItem.objects.filter(owner=request.user).order_by('-created')})
@login_required
@require_POST
def upload_inventory(request):
 """Save a user-uploaded WAV or video file without encoding it."""
 try:
  uploaded=request.FILES.get('file')
  if not uploaded:raise ValueError('Choose an audio or video file.')
  ext=Path(uploaded.name).suffix.lower()
  carrier=next((kind for kind,extensions in EXT.items() if ext in extensions),None)
  if carrier is None:raise ValueError('Only WAV audio and AVI, MP4, MOV, or MKV video are supported.')
  if uploaded.size>MAX_FILE:raise ValueError('Maximum upload size is 50 MB.')
  save_item(request.user,uploaded.read(),Path(uploaded.name).name,carrier,'original')
  messages.success(request,'File uploaded and saved to your inventory.')
 except ValueError as exc:messages.error(request,str(exc))
 return redirect('library')

@login_required
def library(request):
 items=MediaItem.objects.filter(owner=request.user).order_by('-created')
 return render(request,'core/library.html',{'items':items})
@login_required
def download(request,pk):
 item=get_object_or_404(MediaItem,pk=pk,owner=request.user)
 return FileResponse(item.file.open('rb'),as_attachment=True,filename=item.name)
@login_required
@require_POST
def delete(request,pk):
 item=get_object_or_404(MediaItem,pk=pk,owner=request.user)
 item.file.delete(save=False);item.delete();messages.success(request,'File deleted.');return redirect('library')
def tutorial(request):return render(request,'core/tutorial.html')
@login_required
@require_POST
def capacity_view(request):
 try:
  carrier=request.POST.get('carrier','audio');raw,_=get_media(request,carrier)
  if carrier=='video':
   import cv2
   with tempfile.TemporaryDirectory() as d:
    path=Path(d)/('input'+Path(request.FILES['file'].name).suffix) if request.FILES.get('file') else Path(d)/'input.avi'
    path.write_bytes(raw);cap=cv2.VideoCapture(str(path));w=int(cap.get(3));h=int(cap.get(4));cap.release();value=max(0,w*h*3//8-4)
  else:value=stego.capacity(raw,carrier)
  return JsonResponse({'capacity_bytes':value,'note':'Capacity includes encryption overhead; available message text may be smaller.'})
 except Exception as exc:return JsonResponse({'error':str(exc)},status=400)

def features(request):
 return render(request,'core/features.html')
