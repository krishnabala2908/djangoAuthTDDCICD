from django.shortcuts import render
import logging
from django.contrib.auth.decorators import login_required
# Create your views here.

logger = logging.getLogger('django')

@login_required
def home(request):
    # logger.warning('request is processing')
    return render(request, 'core/home.html', {})
