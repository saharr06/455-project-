from django.conf import settings
from django.db import models
class MediaItem(models.Model):
 KIND=[('original','Original'),('encoded','Encoded'),('sample','Sample')]
 owner=models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.CASCADE,related_name='media_items')
 file=models.FileField(upload_to='vault/%Y/%m/')
 name=models.CharField(max_length=180)
 kind=models.CharField(max_length=10,choices=KIND,default='original')
 carrier=models.CharField(max_length=10,default='audio')
 created=models.DateTimeField(auto_now_add=True)
 def __str__(self):return self.name
