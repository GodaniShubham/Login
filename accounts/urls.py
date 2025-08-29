
from django.urls import path
from django.contrib.auth import views as auth_views
from . import views


app_name = "accounts"

urlpatterns = [
    path("register/", views.register_view, name="register"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("profile/", views.profile_view, name="profile"),
    path("dashboard/", views.dashboard_view, name="dashboard"),

    # Forgot & Reset Password
    path("forgot-password/", views.forgot_password_view, name="forgot_password"),
    path("reset-password/<uidb64>/<token>/", views.reset_password_view, name="reset_password"),
    path('forgot-password/', 
        auth_views.PasswordResetView.as_view(
            template_name="accounts/password_reset.html"
        ), 
        name='password_reset'),

    # Email sent confirmation
    path('forgot-password/done/', 
        auth_views.PasswordResetDoneView.as_view(
            template_name="accounts/password_reset_done.html"
        ), 
        name='password_reset_done'),

    # Link in email (confirm new password)
    path('reset/<uidb64>/<token>/',
        auth_views.PasswordResetConfirmView.as_view(
            template_name="accounts/password_reset_confirm.html"
        ), 
        name='password_reset_confirm'),

    # Password successfully reset
    path('reset/done/',
        auth_views.PasswordResetCompleteView.as_view(
            template_name="accounts/password_reset_complete.html"
        ), 
        name='password_reset_complete'),
]
