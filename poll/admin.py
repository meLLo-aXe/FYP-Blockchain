from django.contrib import admin
from . import models

class CandidateAdmin(admin.ModelAdmin):
    readonly_fields = ('count',)  # Replace 'vote_count' with your actual field name

admin.site.register(models.Candidate, CandidateAdmin)

# Register other models as before
admin.site.register(models.Voter)
admin.site.register(models.Vote)
admin.site.register(models.Block)

# ... your existing User admin code below ...
from django.contrib.auth.models import User
from django.contrib.auth.admin import UserAdmin as DefaultUserAdmin
from django.contrib.auth.forms import UserCreationForm
from django import forms
from .models import Voter
from django.contrib import admin

admin.site.site_header = "VoteBlock"
admin.site.site_title = "VoeBlock"
admin.site.index_title = "Welcome to VoteBlock Dashboard"

class UsernameOnlyUserCreationForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ('username',)

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_unusable_password()  # disables login until password is set
        if commit:
            user.save()
        return user

class VoterInline(admin.StackedInline):
    model = Voter
    can_delete = False
    verbose_name_plural = 'Voter Profile'

class CustomUserAdmin(DefaultUserAdmin):
    add_form = UsernameOnlyUserCreationForm
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username',),
        }),
    )
    inlines = (VoterInline,)
    def get_fieldsets(self, request, obj=None):
        if not obj:
            return self.add_fieldsets
        return super().get_fieldsets(request, obj)

admin.site.unregister(User)
admin.site.register(User, CustomUserAdmin)
