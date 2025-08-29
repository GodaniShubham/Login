from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.tokens import default_token_generator
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.core.mail import send_mail
from django.conf import settings

User = get_user_model()

# ------------------ REGISTER ------------------
def register_view(request):
    if request.method == "POST":
        first_name = request.POST.get("first_name")
        last_name = request.POST.get("last_name")
        email = request.POST.get("email")
        username = request.POST.get("username")
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm_password")

        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return redirect("accounts:register")

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already taken.")
            return redirect("accounts:register")

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already registered.")
            return redirect("accounts:register")

        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name
        )
        user.save()
        messages.success(request, "Account created successfully! Please log in.")
        return redirect("accounts:login")  # ✅ Redirect to login page after signup

    return render(request, "accounts/register.html")

# ------------------ LOGIN ------------------
def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            messages.success(request, f"Welcome back, {user.username}!")
            return redirect("accounts:dashboard")  # ✅ dashboard after login
        else:
            messages.error(request, "Invalid username or password.")

    return render(request, "accounts/login.html")

# ------------------ LOGOUT ------------------
def logout_view(request):
    logout(request)
    messages.info(request, "You have been logged out.")
    return redirect("accounts:login")

# ------------------ PROFILE ------------------
@login_required
def profile_view(request):
    return render(request, "accounts/profile.html")

# ------------------ DASHBOARD ------------------
@login_required
def dashboard_view(request):
    return render(request, "accounts/dashboard.html")

# ------------------ FORGOT PASSWORD ------------------
def forgot_password_view(request):
    if request.method == "POST":
        email = request.POST.get("email")
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            messages.error(request, "No account found with this email.")
            return redirect("accounts:forgot_password")

        # Generate reset link
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        reset_link = request.build_absolute_uri(
            f"/accounts/reset-password/{uid}/{token}/"
        )

        # Send email
        subject = "Password Reset Request"
        message = render_to_string("accounts/password_reset_email.html", {
            "user": user,
            "reset_link": reset_link,
        })
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])

        messages.success(request, "Password reset link sent to your email.")
        return redirect("accounts:login")

    return render(request, "accounts/forgot_password.html")

# ------------------ RESET PASSWORD ------------------
def reset_password_view(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (User.DoesNotExist, ValueError, TypeError, OverflowError):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        if request.method == "POST":
            new_password = request.POST.get("password")
            confirm_password = request.POST.get("confirm_password")

            if new_password != confirm_password:
                messages.error(request, "Passwords do not match.")
                return redirect(request.path)

            user.set_password(new_password)
            user.save()
            messages.success(request, "Password reset successful! You can log in now.")
            return redirect("accounts:login")

        return render(request, "accounts/reset_password.html", {"validlink": True})
    else:
        messages.error(request, "Invalid or expired password reset link.")
        return redirect("accounts:forgot_password")
