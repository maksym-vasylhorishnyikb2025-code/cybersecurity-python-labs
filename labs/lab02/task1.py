from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

# Константи безпеки та налаштувань сесії
PBKDF2_ITERATIONS: int = 100_000
SESSION_TIMEOUT_SEC: int = 900

# Регулярний вираз: починається з літери, 3-64 символи, далі @ і домен
EMAIL_REGEX: re.Pattern[str] = re.compile(
    r"^[a-zA-Z][a-zA-Z0-9_.]{2,63}@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+$"
)


class User:
    """Базовий клас облікового запису користувача."""

    def __init__(
        self,
        username: str,
        email: str,
        role: str = "user",
        active: bool = True,
    ) -> None:
        self.username: str = username
        self._email: str = ""
        self.email = email  # Спрацьовує setter із валідацією
        self.role: str = role
        self.active: bool = active
        # Приватні атрибути для хешування пароля (name mangling)
        self.__password_hash: bytes | None = None
        self.__password_salt: bytes | None = None

    @property
    def email(self) -> str:
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        if not isinstance(value, str) or not EMAIL_REGEX.match(value):
            raise ValueError(
                f"Некоректний формат email: '{value}'. "
                "Локальна частина має починатися з літери та містити 3-64 символи."
            )
        self._email = value

    def set_password(self, password: str) -> None:
        """Хешування пароля за допомогою PBKDF2-HMAC-SHA256 з унікальною сіллю."""
        if not password:
            raise ValueError("Пароль не може бути порожнім.")
        self.__password_salt = os.urandom(16)
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )

    def check_password(self, password: str) -> bool:
        """Безпечна перевірка хешу пароля без витоку за часом (timing attack)."""
        if self.__password_hash is None or self.__password_salt is None:
            return False
        candidate = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )
        return hmac.compare_digest(self.__password_hash, candidate)

    def deactivate(self) -> None:
        self.active = False

    def __str__(self) -> str:
        status = "Active" if self.active else "Inactive"
        return (
            f"User(username='{self.username}', email='{self.email}', "
            f"role='{self.role}', status='{status}')"
        )


class Admin(User):
    """Клас адміністратора (приклад наслідування Is-A)."""

    def __init__(
        self,
        username: str,
        email: str,
        permissions: set[str] | None = None,
        active: bool = True,
    ) -> None:
        super().__init__(username=username, email=email, role="admin", active=active)
        # Уникаємо використання mutable об'єкта за замовчуванням
        self.permissions: set[str] = (
            set(permissions) if permissions is not None else set()
        )

    def grant_permission(self, permission: str) -> None:
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self) -> str:
        base_info = super().__str__()
        perms = ", ".join(sorted(self.permissions)) if self.permissions else "None"
        return f"{base_info} | Permissions: [{perms}]"


class Session:
    """Управління життєвим циклом сеансу користувача."""

    def __init__(
        self,
        ip: str,
        login_time: datetime | None = None,
        last_activity: datetime | None = None,
    ) -> None:
        now_utc = datetime.now(tz=timezone.utc)
        self.ip: str = ip
        self.login_time: datetime = login_time or now_utc
        self.last_activity: datetime = last_activity or self.login_time

    def touch(self) -> None:
        """Оновлення часу останньої активності."""
        self.last_activity = datetime.now(tz=timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        """Перевірка активності сесії через об'єкт timedelta."""
        if timeout_sec <= 0:
            raise ValueError("timeout_sec повинен бути додатним числом.")
        now = datetime.now(tz=timezone.utc)
        return (now - self.last_activity) < timedelta(seconds=timeout_sec)


@dataclass(frozen=True)
class AuditRecord:
    """Незмінний запис аудиту (frozen dataclass)."""

    timestamp: datetime
    username: str
    action: str


class AuditLog:
    """Журнал подій безпеки."""

    def __init__(self) -> None:
        self._logs: list[AuditRecord] = []

    def add_log(self, username: str, action: str) -> None:
        self._logs.append(
            AuditRecord(
                timestamp=datetime.now(tz=timezone.utc),
                username=username,
                action=action,
            )
        )

    def show_all(self) -> list[AuditRecord]:
        return list(self._logs)


class UserAccount:
    """Обліковий запис (приклад композиції Has-A: User, Session та AuditLog)."""

    def __init__(
        self,
        user: User,
        session: Session | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:
        self._user: User = user
        self._session: Session | None = session
        self._audit_log: AuditLog = audit_log or AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        if self._user.username != username or not self._user.active:
            self._audit_log.add_log(username, "login_failure")
            return False
        if not self._user.check_password(password):
            self._audit_log.add_log(username, "login_failure")
            return False

        now = datetime.now(tz=timezone.utc)
        self._session = Session(ip=ip, login_time=now, last_activity=now)
        self._audit_log.add_log(username, "login_success")
        return True

    def is_authenticated(self) -> bool:
        if self._session is None:
            return False
        if not self._session.is_active(SESSION_TIMEOUT_SEC):
            self._session = None
            return False
        return True

    def logout(self) -> None:
        if self._session is not None:
            self._session = None
            self._audit_log.add_log(self._user.username, "logout")

    def __getitem__(self, key: str) -> Any:
        if key == "user":
            return self._user
        if key == "session":
            return self._session
        if key == "audit_log":
            return self._audit_log
        raise KeyError(f"Ключ '{key}' не знайдено або доступ до нього заборонено.")

    def __setitem__(self, key: str, value: Any) -> None:
        if key == "user":
            if not isinstance(value, User):
                raise TypeError("Значення для 'user' має бути екземпляром User.")
            self._user = value
        elif key == "session":
            if value is not None and not isinstance(value, Session):
                raise TypeError(
                    "Значення для 'session' має бути екземпляром Session або None."
                )
            self._session = value
        elif key == "audit_log":
            if not isinstance(value, AuditLog):
                raise TypeError(
                    "Значення для 'audit_log' має бути екземпляром AuditLog."
                )
            self._audit_log = value
        else:
            raise KeyError(f"Зміна поля '{key}' заборонена або ключ некоректний.")


if __name__ == "__main__":
    print("=== Демонстрація Завдання 1: ООП Модель Безпеки ===\n")

    # 1. Валідація email та хешування
    print("[1] Створення користувача та валідація email:")
    user = User(username="sec_analyst", email="analyst@corp.ua")
    user.set_password("SecureStudentPass2026!")
    print(f"  Створено: {user}")
    try:
        print("  Спроба встановити некоректний email 'bad_mail@@'...")
        user.email = "bad_mail@@"
    except ValueError as e:
        print(f"  [Валідація спрацювала]: {e}")

    # 2. Наслідування та права Admin
    print("\n[2] Перевірка наслідування та дозволів Admin:")
    admin = Admin(
        username="lead_admin",
        email="root.lead@cyber.ua",
        permissions={"view_logs", "edit_rules"},
    )
    admin.set_password("RootAccessOnly2026#")
    print(f"  Початкові права: {admin}")
    admin.grant_permission("quarantine_host")
    admin.revoke_permission("edit_rules")
    print(f"  Оновлені права:  {admin}")
    print(f"  Чи є дозвіл 'quarantine_host': {admin.has_permission('quarantine_host')}")
    a = Admin("test_admin", "test_admin@cyber.ua", permissions={"add_user"})
    a.set_password("TestAdminPass2026$")
    print(f"  Новий адміністратор: {a}")

    # 3. Аутентифікація, сесії та аудит
    print("\n[3] Тестування UserAccount та AuditLog:")
    audit = AuditLog()
    account = UserAccount(user=user, audit_log=audit)
    print("  Спроба входу з некоректним паролем:")
    res_fail = account.login("sec_analyst", "WrongPassword", "192.168.1.45")
    print(f"  Результат: {res_fail} | Сесія активна: {account.is_authenticated()}")
    print("  Спроба входу з валідним паролем:")
    res_ok = account.login("sec_analyst", "SecureStudentPass2026!", "192.168.1.45")
    print(f"  Результат: {res_ok} | Сесія активна: {account.is_authenticated()}")

    # 4. Імітація закінчення таймауту сесії
    print("\n[4] Перевірка таймауту сесії (імітація зсуву часу):")
    sess = account["session"]
    if sess:
        sess.last_activity = sess.last_activity.replace(year=2020)
    print(
        f"  Перевірка після застаріння: is_authenticated = {account.is_authenticated()}"
    )

    # 5. Повторний логін та вихід
    account.login("sec_analyst", "SecureStudentPass2026!", "10.0.0.12")
    print(f"  Повторний вхід успішний. is_authenticated: {account.is_authenticated()}")
    account.logout()
    print(f"  Після logout(). is_authenticated: {account.is_authenticated()}")

    # 6. Журнал аудиту
    print("\n[5] Вміст AuditLog:")
    for idx, log in enumerate(audit.show_all(), start=1):
        ts = log.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
        print(f"  {idx}. [{ts}] Користувач: '{log.username}' | Подія: '{log.action}'")

    # 7. Захист через магічні методи
    print("\n[6] Перевірка магічних методів __getitem__ / __setitem__:")
    print(f"  account['user']: {account['user']}")
    try:
        _ = account["__password_hash"]
    except KeyError as e:
        print(
            f"  [Захист приватних даних]: Спроба отримати хеш повернула KeyError: {e}"
        )

    print("\n=== Демонстрація успішно завершена ===")
