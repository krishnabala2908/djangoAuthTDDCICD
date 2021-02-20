from django.db import models

# Create your models here.


class Post(models.Model):
    """Model definition for Post."""

    # TODO: Define fields here
    title = models.CharField(max_length=50)
    author = models.CharField(max_length=50)
    slug = models.CharField(max_length=50)

    class Meta:
        """Meta definition for Post."""

        verbose_name = 'Post'
        verbose_name_plural = 'Posts'

    def __str__(self):
        """Unicode representation of Post."""
        return self.title
