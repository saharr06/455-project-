from django.conf import settings
from django.db import migrations,models
import django.db.models.deletion
class Migration(migrations.Migration):
 initial=True
 dependencies=[migrations.swappable_dependency(settings.AUTH_USER_MODEL)]
 operations=[migrations.CreateModel(name='MediaItem',fields=[('id',models.BigAutoField(auto_created=True,primary_key=True,serialize=False,verbose_name='ID')),('file',models.FileField(upload_to='vault/%Y/%m/')),('name',models.CharField(max_length=180)),('kind',models.CharField(choices=[('original','Original'),('encoded','Encoded'),('sample','Sample')],default='original',max_length=10)),('carrier',models.CharField(default='audio',max_length=10)),('created',models.DateTimeField(auto_now_add=True)),('owner',models.ForeignKey(on_delete=django.db.models.deletion.CASCADE,related_name='media_items',to=settings.AUTH_USER_MODEL))])]
