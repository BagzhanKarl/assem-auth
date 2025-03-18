from datetime import datetime, timedelta
import os
import secrets
from typing import Optional, Dict, Tuple, Any, List, Union

import jwt
from fastapi import HTTPException, Request, Response, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel


# Модель ответа для ошибок аутентификации
class AuthError(BaseModel):
    detail: str
    code: str


class ServiceMode:
    """Режимы работы класса авторизации для разных сервисов"""
    FULL = "full"  # Полный доступ (создание и проверка токенов)
    VERIFY_ONLY = "verify"  # Только проверка токенов


class AssemAUTH:
    def __init__(
            self,
            secret_key: str = None,
            algo: str = "HS256",
            access_token_expire_minutes: int = 30,
            refresh_token_expire_days: int = 7,
            token_issuer: str = "jaai-api",
            token_audience: List[str] = None,
            secure_cookies: bool = True,
            cookie_domain: str = None,
            enable_csrf_protection: bool = True,
            enable_jti: bool = True,
            service_mode: str = ServiceMode.FULL
    ):
        """
        Инициализирует сервис аутентификации с настраиваемыми параметрами.

        Args:
            secret_key: Секретный ключ для подписи JWT (если None, генерируется автоматически)
            algo: Алгоритм подписи JWT
            access_token_expire_minutes: Время жизни access токена в минутах
            refresh_token_expire_days: Время жизни refresh токена в днях
            token_issuer: Издатель токена (iss claim)
            token_audience: Целевая аудитория токена (aud claim)
            secure_cookies: Устанавливать ли флаг Secure для cookies
            cookie_domain: Домен для cookies
            enable_csrf_protection: Включить ли защиту от CSRF
            enable_jti: Включить ли уникальные идентификаторы для токенов
            service_mode: Режим работы сервиса (FULL - создание и проверка токенов,
                                              VERIFY_ONLY - только проверка токенов)
        """
        # Если ключ не предоставлен, генерируем безопасный ключ (в продакшне всегда нужно задавать вручную)
        self.secret_key = secret_key or os.environ.get("JWT_SECRET_KEY") or secrets.token_hex(32)
        self.algo = algo
        self.access_token_expire_minutes = access_token_expire_minutes
        self.refresh_token_expire_days = refresh_token_expire_days
        self.token_issuer = token_issuer
        self.token_audience = token_audience or ["jaai-client"]
        self.secure_cookies = secure_cookies
        self.cookie_domain = cookie_domain
        self.enable_csrf_protection = enable_csrf_protection
        self.enable_jti = enable_jti

        # Устанавливаем режим работы сервиса
        self.service_mode = service_mode

        if self.service_mode not in [ServiceMode.FULL, ServiceMode.VERIFY_ONLY]:
            raise ValueError(
                f"Неверный режим сервиса: {service_mode}. Допустимые значения: {ServiceMode.FULL}, {ServiceMode.VERIFY_ONLY}")

        # Инициализация HTTP bearer для получения токена из заголовка Authorization
        self.http_bearer = HTTPBearer(auto_error=False)

        # Внутренний кэш отозванных токенов (в продакшн стоит заменить на Redis)
        self._revoked_tokens = set()

    def create_jwt_token(
            self,
            data: Dict[str, Any],
            expires_delta: Optional[timedelta] = None,
            token_type: str = "access"
    ) -> str:
        """
        Генерирует JWT-токен с улучшенной безопасностью.

        Args:
            data: Полезная нагрузка токена
            expires_delta: Время жизни токена
            token_type: Тип токена ("access" или "refresh")

        Returns:
            Строка JWT-токена

        Raises:
            PermissionError: Если сервис работает в режиме VERIFY_ONLY
        """
        # Проверяем разрешения для текущего режима сервиса
        if self.service_mode == ServiceMode.VERIFY_ONLY:
            raise PermissionError(
                "Данный экземпляр JaaiAuthx работает только в режиме проверки токенов. Создание токенов запрещено.")

        to_encode = data.copy()

        # Устанавливаем время создания и истечения токена
        now = datetime.utcnow()

        if token_type == "access":
            expires_delta = expires_delta or timedelta(minutes=self.access_token_expire_minutes)
        else:
            expires_delta = expires_delta or timedelta(days=self.refresh_token_expire_days)

        expire = now + expires_delta

        # Добавляем стандартные JWT-клеймы для безопасности
        to_encode.update({
            "iat": now,  # Issued At - время создания токена
            "exp": expire,  # Expiration Time - время истечения токена
            "iss": self.token_issuer,  # Issuer - издатель токена
            "aud": self.token_audience,  # Audience - аудитория токена
            "type": token_type,  # Тип токена (access/refresh)
        })

        # Добавляем уникальный идентификатор токена (JWT ID) для возможности отзыва
        if self.enable_jti:
            to_encode["jti"] = secrets.token_hex(16)

        return jwt.encode(to_encode, self.secret_key, algorithm=self.algo)

    def create_tokens(
            self,
            user_id: Union[int, str],
            additional_data: Dict[str, Any] = None
    ) -> Tuple[str, str, str]:
        """
        Создаёт access и refresh токены, а также csrf-токен при необходимости.

        Args:
            user_id: Идентификатор пользователя
            additional_data: Дополнительные данные для включения в токен

        Returns:
            Кортеж (access_token, refresh_token, csrf_token)

        Raises:
            PermissionError: Если сервис работает в режиме VERIFY_ONLY
        """
        # Проверяем разрешения для текущего режима сервиса
        if self.service_mode == ServiceMode.VERIFY_ONLY:
            raise PermissionError(
                "Данный экземпляр JaaiAuthx работает только в режиме проверки токенов. Создание токенов запрещено.")

        data = {"sub": str(user_id)}

        # Добавляем дополнительные данные в токен (например, роли пользователя)
        if additional_data:
            data.update(additional_data)

        access_token = self.create_jwt_token(
            data=data,
            expires_delta=timedelta(minutes=self.access_token_expire_minutes),
            token_type="access"
        )

        refresh_token = self.create_jwt_token(
            data=data,
            expires_delta=timedelta(days=self.refresh_token_expire_days),
            token_type="refresh"
        )

        csrf_token = ""
        if self.enable_csrf_protection:
            csrf_token = secrets.token_hex(16)

        return access_token, refresh_token, csrf_token

    def set_tokens_in_cookies(
            self,
            response: Response,
            access_token: str,
            refresh_token: str,
            csrf_token: str = ""
    ) -> None:
        """
        Устанавливает токены в защищенные куки.

        Args:
            response: Объект Response FastAPI
            access_token: JWT access токен
            refresh_token: JWT refresh токен
            csrf_token: CSRF токен (если включена защита)

        Raises:
            PermissionError: Если сервис работает в режиме VERIFY_ONLY
        """
        # Проверяем разрешения для текущего режима сервиса
        if self.service_mode == ServiceMode.VERIFY_ONLY:
            raise PermissionError(
                "Данный экземпляр JaaiAuthx работает только в режиме проверки токенов. Установка токенов запрещена.")

        # Определяем общие параметры безопасности для cookies
        cookie_params = {
            "httponly": True,  # Недоступно для JavaScript
            "samesite": "lax",  # Защита от CSRF
            "secure": self.secure_cookies,  # Только по HTTPS
        }

        if self.cookie_domain:
            cookie_params["domain"] = self.cookie_domain

        # Устанавливаем время истечения cookie для токенов
        access_expires = self.access_token_expire_minutes * 60
        refresh_expires = self.refresh_token_expire_days * 24 * 60 * 60

        # Устанавливаем куки для токенов
        response.set_cookie(
            key="access_token",
            value=access_token,
            max_age=access_expires,
            **cookie_params
        )

        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            max_age=refresh_expires,
            **cookie_params
        )

        # Если включена защита от CSRF, устанавливаем CSRF токен
        # CSRF токен не должен быть httponly, чтобы JavaScript имел к нему доступ
        if self.enable_csrf_protection and csrf_token:
            response.set_cookie(
                key="csrf_token",
                value=csrf_token,
                max_age=access_expires,
                httponly=False,  # Доступно для JavaScript
                samesite="lax",
                secure=self.secure_cookies
            )

            # Также отправляем CSRF-токен в заголовке для удобства
            response.headers["X-CSRF-Token"] = csrf_token

    def verify_token(
            self,
            token: str,
            token_type: str = "access"
    ) -> Dict[str, Any]:
        """
        Проверяет JWT токен и возвращает его содержимое.
        Эта функция доступна в любом режиме работы сервиса.

        Args:
            token: JWT токен для проверки
            token_type: Ожидаемый тип токена ("access" или "refresh")

        Returns:
            Содержимое токена

        Raises:
            HTTPException: Если токен недействителен или истек
        """
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=AuthError(detail="Токен не предоставлен", code="token_missing").dict()
            )

        try:
            # Декодируем и проверяем токен
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algo],
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_iss": True,
                    "verify_aud": True,
                    "require": ["exp", "iat", "iss", "aud", "sub", "type"]
                },
                issuer=self.token_issuer,
                audience=self.token_audience
            )

            # Проверяем тип токена
            if payload.get("type") != token_type:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=AuthError(detail=f"Неверный тип токена, ожидался {token_type}",
                                     code="invalid_token_type").dict()
                )

            # Проверяем, не отозван ли токен
            if self.enable_jti and payload.get("jti") in self._revoked_tokens:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=AuthError(detail="Токен был отозван", code="token_revoked").dict()
                )

            return payload

        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=AuthError(detail="Токен истек", code="token_expired").dict()
            )
        except jwt.InvalidIssuerError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=AuthError(detail="Неверный издатель токена", code="invalid_issuer").dict()
            )
        except jwt.InvalidAudienceError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=AuthError(detail="Неверная аудитория токена", code="invalid_audience").dict()
            )
        except jwt.InvalidTokenError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=AuthError(detail="Неверный токен", code="invalid_token").dict()
            )

    def get_token_from_request(self, request: Request) -> Tuple[str, str]:
        """
        Получает токен из запроса, проверяя cookies и заголовок Authorization.
        Эта функция доступна в любом режиме работы сервиса.

        Args:
            request: Объект запроса FastAPI

        Returns:
            Кортеж (токен, источник токена)
        """
        # Проверяем cookies сначала
        token = request.cookies.get("access_token")
        source = "cookie"

        # Если токена нет в cookie, проверяем заголовок Authorization
        if not token:
            auth = request.headers.get("Authorization")
            if auth and auth.startswith("Bearer "):
                token = auth.replace("Bearer ", "")
                source = "header"

        return token, source

    def get_token_payload(
            self,
            request: Request,
            verify_csrf: bool = True
    ) -> Dict[str, Any]:
        """
        Получает полную полезную нагрузку токена, включая все дополнительные данные.

        Args:
            request: Объект запроса FastAPI
            verify_csrf: Проверять ли CSRF токен для запросов не на чтение

        Returns:
            Словарь с содержимым токена, включая user_id (sub) и все дополнительные данные

        Raises:
            HTTPException: Если пользователь не аутентифицирован или произошла ошибка
        """
        token, source = self.get_token_from_request(request)

        # Проверяем CSRF токен, если включена защита и это небезопасный метод
        if (self.enable_csrf_protection and
                verify_csrf and
                source == "cookie" and
                request.method not in ["GET", "HEAD", "OPTIONS"]):

            csrf_cookie = request.cookies.get("csrf_token")
            csrf_header = request.headers.get("X-CSRF-Token")

            if not csrf_cookie or not csrf_header or csrf_cookie != csrf_header:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=AuthError(detail="Неверный CSRF-токен", code="invalid_csrf").dict()
                )

        # Проверяем access токен и возвращаем его содержимое
        return self.verify_token(token, "access")

    def get_current_user(
            self,
            request: Request,
            verify_csrf: bool = True
    ) -> str:
        """
        Получает идентификатор текущего аутентифицированного пользователя.

        Args:
            request: Объект запроса FastAPI
            verify_csrf: Проверять ли CSRF токен для запросов не на чтение

        Returns:
            Идентификатор пользователя

        Raises:
            HTTPException: Если пользователь не аутентифицирован или произошла ошибка
        """
        payload = self.get_token_payload(request, verify_csrf)
        return payload["sub"]

    def get_user_data(
            self,
            request: Request,
            key: str = None,
            verify_csrf: bool = True
    ) -> Any:
        """
        Получает данные пользователя из токена.

        Args:
            request: Объект запроса FastAPI
            key: Ключ для получения конкретного поля из токена (если None, возвращается весь payload)
            verify_csrf: Проверять ли CSRF токен для запросов не на чтение

        Returns:
            Значение запрошенного поля или весь payload токена, если key=None

        Raises:
            HTTPException: Если пользователь не аутентифицирован или произошла ошибка
            KeyError: Если запрошенный ключ отсутствует в токене
        """
        payload = self.get_token_payload(request, verify_csrf)

        # Если ключ не указан, возвращаем весь payload
        if key is None:
            return payload

        # Если ключ указан, пытаемся получить его значение
        if key in payload:
            return payload[key]

        # Если ключ не найден, возвращаем None
        return None

    def get_current_user_dependency(self, verify_csrf: bool = True):
        """
        Создает зависимость FastAPI для получения текущего пользователя.
        Эта функция доступна в любом режиме работы сервиса.

        Args:
            verify_csrf: Проверять ли CSRF токен

        Returns:
            Callable для использования в качестве зависимости
        """

        async def _get_current_user(request: Request):
            return self.get_current_user(request, verify_csrf)

        return _get_current_user

    def get_user_data_dependency(self, key: str = None, verify_csrf: bool = True):
        """
        Создает зависимость FastAPI для получения данных пользователя из токена.

        Args:
            key: Ключ для получения конкретного поля из токена (если None, возвращается весь payload)
            verify_csrf: Проверять ли CSRF токен

        Returns:
            Callable для использования в качестве зависимости
        """

        async def _get_user_data(request: Request):
            return self.get_user_data(request, key, verify_csrf)

        return _get_user_data

    def refresh_access_token(
            self,
            request: Request,
            response: Response
    ) -> Dict[str, str]:
        """
        Обновляет access_token, используя refresh_token.

        Args:
            request: Объект запроса FastAPI
            response: Объект ответа FastAPI

        Returns:
            Словарь с сообщением об успехе

        Raises:
            PermissionError: Если сервис работает в режиме VERIFY_ONLY
            HTTPException: Если refresh_token недействителен или истек
        """
        # Проверяем разрешения для текущего режима сервиса
        if self.service_mode == ServiceMode.VERIFY_ONLY:
            raise PermissionError(
                "Данный экземпляр JaaiAuthx работает только в режиме проверки токенов. Обновление токенов запрещено.")

        refresh_token = request.cookies.get("refresh_token")

        # Проверяем refresh токен
        payload = self.verify_token(refresh_token, "refresh")

        # Получаем данные пользователя из токена
        user_id = payload["sub"]

        # Сохраняем дополнительные данные из старого токена
        additional_data = {k: v for k, v in payload.items()
                           if k not in ["exp", "iat", "iss", "aud", "sub", "jti", "type"]}

        # Создаем новые токены
        access_token, new_refresh_token, csrf_token = self.create_tokens(
            user_id,
            additional_data
        )

        # Отзываем старый refresh токен, если есть поддержка jti
        if self.enable_jti and "jti" in payload:
            self._revoked_tokens.add(payload["jti"])

        # Устанавливаем новые токены в куки
        self.set_tokens_in_cookies(response, access_token, new_refresh_token, csrf_token)

        return {
            "message": "Токены успешно обновлены",
            "code": "tokens_refreshed",
            "user_id": user_id
        }

    def logout(self, request: Request, response: Response) -> Dict[str, str]:
        """
        Выполняет выход пользователя, отзывая токены.

        Args:
            request: Объект запроса FastAPI
            response: Объект ответа FastAPI

        Returns:
            Словарь с сообщением об успехе

        Raises:
            PermissionError: Если сервис работает в режиме VERIFY_ONLY
        """
        # Проверяем разрешения для текущего режима сервиса
        if self.service_mode == ServiceMode.VERIFY_ONLY:
            raise PermissionError(
                "Данный экземпляр JaaiAuthx работает только в режиме проверки токенов. Выход запрещен.")

        # Отзываем токены, если включена поддержка jti
        if self.enable_jti:
            # Получаем текущие токены
            access_token = request.cookies.get("access_token")
            refresh_token = request.cookies.get("refresh_token")

            # Отзываем токены, если они существуют
            try:
                if access_token:
                    access_payload = jwt.decode(
                        access_token,
                        self.secret_key,
                        algorithms=[self.algo],
                        options={"verify_exp": False}  # Пропускаем проверку срока действия
                    )
                    if "jti" in access_payload:
                        self._revoked_tokens.add(access_payload["jti"])

                if refresh_token:
                    refresh_payload = jwt.decode(
                        refresh_token,
                        self.secret_key,
                        algorithms=[self.algo],
                        options={"verify_exp": False}  # Пропускаем проверку срока действия
                    )
                    if "jti" in refresh_payload:
                        self._revoked_tokens.add(refresh_payload["jti"])
            except:
                # Игнорируем ошибки при декодировании токенов
                pass

        # Удаляем куки
        response.delete_cookie(key="access_token", path="/", domain=self.cookie_domain)
        response.delete_cookie(key="refresh_token", path="/", domain=self.cookie_domain)

        if self.enable_csrf_protection:
            response.delete_cookie(key="csrf_token", path="/", domain=self.cookie_domain)

        return {"message": "Выход выполнен успешно", "code": "logout_success"}

    def revoke_token(self, token: str) -> Dict[str, str]:
        """
        Отзывает указанный токен, добавляя его в черный список.

        Args:
            token: JWT токен для отзыва

        Returns:
            Словарь с сообщением об успехе

        Raises:
            PermissionError: Если сервис работает в режиме VERIFY_ONLY
            HTTPException: Если токен недействителен или не содержит JTI
        """
        # Проверяем разрешения для текущего режима сервиса
        if self.service_mode == ServiceMode.VERIFY_ONLY:
            raise PermissionError(
                "Данный экземпляр JaaiAuthx работает только в режиме проверки токенов. Отзыв токенов запрещен.")

        if not self.enable_jti:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=AuthError(detail="Отзыв токенов не включен", code="revocation_disabled").dict()
            )

        try:
            # Декодируем токен, пропуская проверку срока действия
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algo],
                options={"verify_exp": False}
            )

            if "jti" not in payload:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=AuthError(detail="Токен не содержит JTI", code="no_jti").dict()
                )

            # Добавляем JTI в черный список
            self._revoked_tokens.add(payload["jti"])

            return {"message": "Токен успешно отозван", "code": "token_revoked"}

        except jwt.InvalidTokenError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=AuthError(detail="Неверный токен", code="invalid_token").dict()
            )