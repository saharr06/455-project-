"""LSB steganography for WAV PCM and lossless FFV1 AVI.
Format: 4-byte big-endian payload length + encrypted or plain envelope.
Avoid lossy recompression after encoding: it destroys least significant bits.
"""
import io,os,struct,wave
from pathlib import Path
import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
MAX_PAYLOAD=2_000_000

def pack_file(data, filename, password=''):
 """Wrap a binary attachment with its original filename; encrypt when requested."""
 import json
 if not data: raise ValueError('Choose a nonempty secret file.')
 name=Path(filename).name
 header=json.dumps({'name':name},ensure_ascii=False).encode('utf-8')
 if len(header)>4096: raise ValueError('Filename is too long.')
 return protect(b'SF2F'+struct.pack('>H',len(header))+header+data,password)

def protect(data,password=''):
 if password:
  salt=os.urandom(16);nonce=os.urandom(12)
  key=Scrypt(salt=salt,length=32,n=2**14,r=8,p=1).derive(password.encode())
  return b'SV1E'+salt+nonce+AESGCM(key).encrypt(nonce,data,None)
 return b'SV1P'+data

def unpack_content(blob,password=''):
 """Return (kind, original filename, bytes); legacy text remains readable."""
 import json
 if blob.startswith(b'SV1P'): data=blob[4:]
 elif blob.startswith(b'SV1E'):
  if not password:raise ValueError('This message requires a password.')
  salt,nonce,cipher=blob[4:20],blob[20:32],blob[32:]
  key=Scrypt(salt=salt,length=32,n=2**14,r=8,p=1).derive(password.encode())
  try:data=AESGCM(key).decrypt(nonce,cipher,None)
  except Exception:raise ValueError('Incorrect password or damaged hidden message.') from None
 else:raise ValueError('No supported hidden content was found.')
 if data.startswith(b'SF2F'):
  if len(data)<6:raise ValueError('Damaged hidden file header.')
  size=struct.unpack('>H',data[4:6])[0]
  if size>4096 or len(data)<6+size:raise ValueError('Damaged hidden file header.')
  try: name=Path(json.loads(data[6:6+size].decode('utf-8'))['name']).name
  except Exception:raise ValueError('Damaged hidden file header.') from None
  return 'file',name,data[6+size:]
 if data.startswith(b'SF2T'):
  return 'text','',data[4:]
 return 'text','',data # legacy text

def pack(message,password=''):
 data=message.encode('utf-8')
 if not data:raise ValueError('Please enter a message.')
 return protect(b'SF2T'+data,password)

def unpack(blob,password=''):
 kind,_,data=unpack_content(blob,password)
 if kind!='text':raise ValueError('Hidden content is a file, not text.')
 return data.decode('utf-8')

def insert(bits,payload):
 if len(payload)>MAX_PAYLOAD:raise ValueError('Message is too large.')
 data=struct.pack('>I',len(payload))+payload
 bitstream=np.unpackbits(np.frombuffer(data,dtype=np.uint8))
 if bitstream.size>bits.size:raise ValueError(f'Carrier too small. Capacity: {max(0,(bits.size//8)-4)} bytes.')
 bits[:bitstream.size]=(bits[:bitstream.size]&254)|bitstream
 return bits

def extract(bits):
 if bits.size<32:raise ValueError('Carrier is too small.')
 length=struct.unpack('>I',np.packbits(bits[:32]&1).tobytes())[0]
 if not 4<=length<=MAX_PAYLOAD or (length+4)*8>bits.size:raise ValueError('No supported hidden message was found.')
 return np.packbits(bits[32:(length+4)*8]&1).tobytes()

def wav_encode(raw,payload):
 with wave.open(io.BytesIO(raw),'rb') as wf:
  params=wf.getparams();frames=wf.readframes(wf.getnframes())
 if params.comptype!='NONE' or params.sampwidth not in (1,2,3,4):raise ValueError('Only uncompressed PCM WAV is supported.')
 arr=np.frombuffer(frames,dtype=np.uint8).copy()
 # Use low byte of each sample, preserving the other bytes.
 indices=np.arange(0,len(arr),params.sampwidth)
 selected=arr[indices].copy();insert(selected,payload);arr[indices]=selected
 out=io.BytesIO()
 with wave.open(out,'wb') as wf:wf.setparams(params);wf.writeframes(arr.tobytes())
 return out.getvalue(),len(indices)//8-4

def wav_decode(raw):
 with wave.open(io.BytesIO(raw),'rb') as wf:
  width=wf.getsampwidth();frames=wf.readframes(wf.getnframes())
 return extract(np.frombuffer(frames,dtype=np.uint8)[::width])

def video_process(source_path,output_path,payload=None):
 import cv2
 cap=cv2.VideoCapture(str(source_path))
 if not cap.isOpened():raise ValueError('Cannot read video. Try an AVI or MP4 input.')
 fps=cap.get(cv2.CAP_PROP_FPS) or 24
 width=int(cap.get(cv2.CAP_PROP_FRAME_WIDTH));height=int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
 count=int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
 if width<1 or height<1:cap.release();raise ValueError('Invalid video dimensions.')
 if payload is None:
  ok,frame=cap.read();cap.release()
  if not ok:raise ValueError('Video contains no frames.')
  return extract(frame.reshape(-1))
 # First frame holds the payload; FFV1 lossless codec preserves its LSBs.
 ok,first=cap.read()
 if not ok:cap.release();raise ValueError('Video contains no frames.')
 insert(first.reshape(-1),payload)
 writer=cv2.VideoWriter(str(output_path),cv2.VideoWriter_fourcc(*'FFV1'),fps,(width,height))
 if not writer.isOpened():cap.release();raise ValueError('FFV1 video encoder unavailable in OpenCV.')
 try:
  writer.write(first)
  while True:
   ok,frame=cap.read()
   if not ok:break
   writer.write(frame)
 finally:writer.release();cap.release()
 return max(0,width*height*3//8-4)

def capacity(raw,carrier):
 if carrier=='audio':
  with wave.open(io.BytesIO(raw),'rb') as wf:return max(0,wf.getnframes()//8-4)
 return None
