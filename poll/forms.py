from django import forms
from django.contrib.auth import get_user_model

User = get_user_model()

class SetPasswordForm(forms.Form):
    username = forms.CharField()
    new_password = forms.CharField(widget=forms.PasswordInput())

    def clean_username(self):
        username = self.cleaned_data['username']
        if not User.objects.filter(username=username).exists():
            raise forms.ValidationError("User does not exist.")
        return username
