from sqladmin import Admin, ModelView
from sqladmin.authentication import AuthenticationBackend
from fastapi import Request
from sqlalchemy.orm import Session
from .database import engine
from . import models, crud, auth


class AdminAuth(AuthenticationBackend):
    async def login(self, request: Request) -> bool:
        form = await request.form()
        username = form.get("username")
        password = form.get("password")

        with Session(engine) as session:
            user = crud.get_user_by_username(session, username)
            if user and user.username == "admin" and auth.verify_password(password, user.hashed_password):
                request.session.update({"token": "admin-token"})
                return True
        return False

    async def logout(self, request: Request) -> bool:
        request.session.clear()
        return True

    async def authenticate(self, request: Request) -> bool:
        token = request.session.get("token")
        return token == "admin-token"


class UserAdmin(ModelView, model=models.User):
    column_list = [models.User.id, models.User.username, models.User.email]
    column_details_exclude_list = [models.User.hashed_password]
    column_searchable_list = [models.User.username, models.User.email]
    column_sortable_list = [models.User.id, models.User.username]

    can_create = False
    can_edit = False
    can_delete = False

    def is_visible(self, request: Request) -> bool:
        return True

    def is_accessible(self, request: Request) -> bool:
        return True


class MessageAdmin(ModelView, model=models.Message):
    column_list = [
        models.Message.id,
        models.Message.sender,
        models.Message.receiver,
        models.Message.timestamp
    ]
    column_details_exclude_list = [models.Message.encrypted_text, models.Message.encrypted_key]
    column_searchable_list = [models.Message.encrypted_text]
    column_sortable_list = [models.Message.id, models.Message.timestamp]

    column_labels = {
        models.Message.sender: "Отправитель",
        models.Message.receiver: "Получатель",
        models.Message.timestamp: "Время отправки"
    }


def setup_admin(app):
    authentication_backend = AdminAuth(secret_key="your-secret-key-here")
    admin = Admin(app, engine, authentication_backend=authentication_backend)

    admin.add_view(UserAdmin)
    admin.add_view(MessageAdmin)

    return admin