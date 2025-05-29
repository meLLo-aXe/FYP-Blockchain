from django.shortcuts import render,redirect
from . import models
import math
from datetime import datetime
from django.contrib.admin.forms import AuthenticationForm
import time, datetime
from hashlib import sha512, sha256
from .merkleTree import merkleTree
import uuid
from django.contrib.auth.hashers import make_password
from .forms import SetPasswordForm
from django.contrib.auth import logout
from django.contrib.auth import get_user_model
from django.conf import settings
from .models import Voter
from django.contrib.auth.views import LoginView
from django.contrib import messages
from django.shortcuts import redirect
from django.contrib.auth.decorators import login_required


resultCalculated = False

class CustomLoginView(LoginView):
    template_name = 'poll/login.html'

    def form_valid(self, form):
        messages.success(self.request, 'Login successful!')
        return super().form_valid(form)

    def form_invalid(self, form):
        messages.error(self.request, 'Login failed. Please check your credentials.')
        return self.render_to_response(self.get_context_data(form=form))

def home(request):
    return render(request, 'poll/home.html')

@login_required(login_url='login')
def vote(request):
    voter = models.Voter.objects.filter(user=request.user).first()

    if voter.has_voted:
        messages.info(request, "You have already voted. Thank you for participating!")
        return redirect('home')  # or whichever url name you want

    candidates = models.Candidate.objects.all()
    context = {'candidates': candidates}
    return render(request, 'poll/vote.html', context)

from django.contrib.auth import authenticate, login as auth_login
from django.shortcuts import render, redirect
from django.contrib import messages

def login(request):
    if request.method == 'POST':
        username = request.POST.get('username').strip()
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)

        if user is not None:
            auth_login(request, user)
            messages.success(request, "Login successful!")
            return redirect('vote')  # Replace with your app's page
        else:
            messages.error(request, "Invalid username or password.")

    return render(request, 'poll/login.html')


from django.contrib.auth.models import User
from django.contrib import messages
from django.shortcuts import render, redirect
from .models import Voter

def signup(request):
    if request.method == 'POST':
        username = request.POST['username'].strip()
        password = request.POST['password']
        confirm = request.POST['confirm_password']
        n = request.POST.get('n')
        e = request.POST.get('e')

        if password != confirm:
            messages.error(request, "Passwords do not match.")
            return render(request, 'poll/signup.html')

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            messages.error(request, "Username not registered by admin.")
            return render(request, 'poll/signup.html')

        if user.has_usable_password():
            messages.error(request, "You have already signed up.")
            return render(request, 'poll/signup.html')

        # Set the password correctly
        user.set_password(password)
        user.save()

        # Create linked Voter object
        if not hasattr(user, 'voter'):
            Voter.objects.create(user=user, public_key_n=n, public_key_e=e)

        messages.success(request, "Signup successful. Please log in.")
        return redirect('login')

    return render(request, 'poll/signup.html')

User = get_user_model()

def logout_user(request):
    logout(request)  # This clears the session and logs the user out
    return redirect('login')  # Redirect to login page after logout

def create(request, pk):
    print(request.user)
    voter = models.Voter.objects.filter(user__username=request.user.username).first()
    context = {}

    if request.method == 'POST' and request.user.is_authenticated:
        
        if voter.has_voted:
            # User already voted - block further voting
            context['status'] = "You have already cast your vote. Multiple voting is not allowed."
            context['error'] = True
            return render(request, 'poll/failure.html', context)

        vote = pk
        lenVoteList = len(models.Vote.objects.all())
        if lenVoteList > 0:
            block_id = math.floor(lenVoteList / 5) + 1
        else:
            block_id = 1

        priv_key = {
            'n': int(request.POST.get('privateKey_n')),
            'd': int(request.POST.get('privateKey_d'))
        }
        pub_key = {
            'n': int(voter.public_key_n),
            'e': int(voter.public_key_e)
        }
        timestamp = datetime.datetime.now().timestamp()
        ballot = "{}|{}".format(vote, timestamp)
        print('\ncasted ballot: {}\n'.format(ballot))
        h = int.from_bytes(sha512(ballot.encode()).digest(), byteorder='big')
        signature = pow(h, priv_key['d'], priv_key['n'])
        hfromSignature = pow(signature, pub_key['e'], pub_key['n'])

        if hfromSignature == h:
            new_vote = models.Vote(vote=pk)
            new_vote.block_id = block_id
            new_vote.save()

            # Mark voter as having voted
            voter.has_voted = True
            voter.save()

            status = 'Ballot signed successfully'
            error = False
        else:
            status = 'Authentication Error'
            error = True

        context = {
            'ballot': ballot,
            'signature': signature,
            'status': status,
            'error': error,
        }
        print(error)

        if not error:
            return render(request, 'poll/status.html', context)

    return render(request, 'poll/failure.html', context)


prev_hash = '0' * 64

def seal(request):

    if request.method == 'POST':

        if (len(models.Vote.objects.all()) % 5 != 0):
            redirect("/")
        else:
            global prev_hash
            transactions = models.Vote.objects.order_by('block_id').reverse()
            transactions = list(transactions)[:5]
            block_id = transactions[0].block_id

            str_transactions = [str(x) for x in transactions]

            merkle_tree = merkleTree.merkleTree()
            merkle_tree.makeTreeFromArray(str_transactions)
            merkle_hash = merkle_tree.calculateMerkleRoot()

            nonce = 0
            timestamp = datetime.datetime.now().timestamp()

            while True:
                self_hash = sha256('{}{}{}{}'.format(prev_hash, merkle_hash, nonce, timestamp).encode()).hexdigest()
                if self_hash[0] == '0':
                    break
                nonce += 1
            
            block = models.Block(id=block_id,prev_hash=prev_hash,self_hash=self_hash,merkle_hash=merkle_hash,nonce=nonce,timestamp=timestamp)
            prev_hash = self_hash
            block.save()
            print('Block {} has been mined'.format(block_id))

    return redirect("home")



def retDate(v):
    v.timestamp = datetime.datetime.fromtimestamp(v.timestamp)
    return v

def verify(request):
    if request.method == 'GET':
        verification = ''
        tampered_block_list = verifyVotes()
        votes = []
        if tampered_block_list:
            verification = 'Verification Failed. Following blocks have been tampered --> {}.\
                The authority will resolve the issue'.format(tampered_block_list)
            error = True
        else:
            verification = 'Verification successful. All votes are intact!'
            error = False
            votes = models.Vote.objects.order_by('timestamp')
            votes = [retDate(x) for x in votes]
            
        context = {'verification':verification, 'error':error, 'votes':votes}
        return render(request, 'poll/verification.html', context)

from django.db.models import Count

@login_required(login_url='login')
def result(request):
    if request.method == "GET":
        voteVerification = verifyVotes()
        if len(voteVerification):
            return render(request, 'poll/verification.html', {
                'verification': f"Verification failed. Votes have been tampered in following blocks --> {voteVerification}. The authority will resolve the issue",
                'error': True
            })

        # Reset all candidate counts to zero first
        models.Candidate.objects.update(count=0)

        # Count votes fresh every time
        list_of_votes = models.Vote.objects.all()
        for vote in list_of_votes:
            candidate = models.Candidate.objects.filter(candidateID=vote.vote).first()
            if candidate:
                candidate.count += 1
                candidate.save()

        # Get candidates sorted by count descending
        candidates = models.Candidate.objects.order_by('-count')

        winner = candidates.first() if candidates else None

        context = {
            "candidates": candidates,
            "winner": winner
        }
        return render(request, 'poll/results.html', context)



def verifyVotes():
    block_count = models.Block.objects.count()
    tampered_block_list = []

    for i in range(1, block_count + 1):
        block = models.Block.objects.get(id=i)
        transactions = models.Vote.objects.filter(block_id=i)
        str_transactions = [str(x) for x in transactions]

        merkle_tree = merkleTree(str_transactions)
        merkle_root = merkle_tree.getMerkleRoot()

        if block.merkle_hash == merkle_root:
            continue
        else:
            tampered_block_list.append(i)

    return tampered_block_list

def custom_404(request, exception):
    return render(request, '404.html', status=404)


