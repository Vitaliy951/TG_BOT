import asyncio
import json
import logging
import os
import random
import urllib.parse
from typing import Dict, List, Optional, Any

import aiohttp
from aiogram import Bot, Dispatcher, types
from aiogram.filters import Command
from dotenv import load_dotenv

# ---------- Настройка логирования ----------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# ---------- Загрузка переменных окружения ----------
load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
PANEL_URL = os.getenv("PANEL_URL")
PANEL_LOGIN = os.getenv("PANEL_LOGIN")
PANEL_PASSWORD = os.getenv("PANEL_PASSWORD")
SPONSOR_TAG = os.getenv("SPONSOR_TAG", "")  # опционально

# Таймауты (можно переопределить в .env)
PANEL_TIMEOUT = float(os.getenv("PANEL_TIMEOUT", "10"))
PROXY_CHECK_TIMEOUT = float(os.getenv("PROXY_CHECK_TIMEOUT", "1.5"))
RETRY_COUNT = int(os.getenv("RETRY_COUNT", "3"))
RETRY_DELAY = float(os.getenv("RETRY_DELAY", "1.0"))

# Проверка обязательных переменных
required_vars = {
    "BOT_TOKEN": BOT_TOKEN,
    "PANEL_URL": PANEL_URL,
    "PANEL_LOGIN": PANEL_LOGIN,
    "PANEL_PASSWORD": PANEL_PASSWORD,
}
missing = [name for name, value in required_vars.items() if not value]
if missing:
    raise ValueError(f"Missing required env vars: {', '.join(missing)}")

# Извлечение хоста панели (для проверки прокси, если понадобится)
try:
    parsed = urllib.parse.urlparse(PANEL_URL)
    SERVER_HOST = parsed.hostname
except Exception as e:
    logger.error(f"Не удалось распарсить PANEL_URL: {e}")
    SERVER_HOST = None

if not SERVER_HOST:
    logger.warning("SERVER_HOST не определён – проверка доступности прокси может работать некорректно.")

# Предупреждение о HTTP (небезопасно)
if parsed.scheme == "http":
    logger.warning("⚠️ Панель доступна по HTTP – пароль передаётся в открытом виде! Рекомендуется использовать HTTPS.")

# ---------- Инициализация бота ----------
bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

# ---------- Вспомогательные функции ----------
async def fetch_with_retry(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    *,
    retries: int = RETRY_COUNT,
    delay: float = RETRY_DELAY,
    **kwargs
) -> Optional[aiohttp.ClientResponse]:
    """Выполняет HTTP-запрос с повторными попытками при ошибках."""
    for attempt in range(1, retries + 1):
        try:
            resp = await session.request(method, url, timeout=aiohttp.ClientTimeout(total=PANEL_TIMEOUT), **kwargs)
            # Если статус 5xx – считаем временной ошибкой и повторяем
            if 500 <= resp.status < 600:
                logger.warning(f"Статус {resp.status} на {url}, попытка {attempt}/{retries}")
                if attempt == retries:
                    return resp
                await asyncio.sleep(delay * attempt)
                continue
            return resp
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.warning(f"Ошибка запроса к {url}: {e}, попытка {attempt}/{retries}")
            if attempt == retries:
                raise
            await asyncio.sleep(delay * attempt)
    return None

async def check_proxy(host: str, port: int) -> bool:
    """Проверяет доступность прокси (TCP-коннект)."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=PROXY_CHECK_TIMEOUT
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception as e:
        logger.debug(f"Прокси {host}:{port} недоступен: {e}")
        return False

async def get_panel_cookies(session: aiohttp.ClientSession) -> Optional[Dict[str, str]]:
    """Авторизуется на панели и возвращает cookies."""
    base_url = PANEL_URL.rstrip('/')
    login_url = urllib.parse.urljoin(PANEL_URL, "/login")
    credentials = {"username": PANEL_LOGIN, "password": PANEL_PASSWORD}

    try:
        resp = await fetch_with_retry(
            session, "POST", login_url,
            data=credentials,
            retries=RETRY_COUNT
        )
        if resp is None:
            logger.error("Не удалось выполнить запрос к /login")
            return None
        if resp.status != 200:
            logger.error(f"Ошибка авторизации: статус {resp.status}")
            return None
        # Возвращаем cookies как словарь
        return {key: value.value for key, value in resp.cookies.items()}
    except Exception as e:
        logger.error(f"Исключение при авторизации: {e}")
        return None

async def fetch_inbounds(session: aiohttp.ClientSession, cookies: Dict[str, str]) -> Optional[List[Dict[str, Any]]]:
    """Получает список inbound'ов с панели."""
    base_url = PANEL_URL.rstrip('/')
    """api_url = urllib.parse.urljoin(PANEL_URL, "/xui/API/inbounds")"""
    api_url = f"{base_url}/panel/api/inbounds/list"
    try:
        resp = await fetch_with_retry(
            session, "GET", api_url,
            cookies=cookies,
            retries=RETRY_COUNT
        )
        if resp is None or resp.status != 200:
            logger.error(f"Не удалось получить inbounds: статус {resp.status if resp else 'нет ответа'}")
            return None
        data = await resp.json()
        return data.get("obj", [])
    except json.JSONDecodeError as e:
        logger.error(f"Ошибка парсинга JSON от панели: {e}")
        return None
    except Exception as e:
        logger.error(f"Исключение при получении inbounds: {e}")
        return None

def extract_mtproto_proxy(inbound: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Извлекает данные MTProto-прокси из одного inbound'а."""
    if inbound.get("protocol") != "mtproto":
        return None
    try:
        settings = json.loads(inbound.get("settings", "{}"))
        stream_settings = json.loads(inbound.get("streamSettings", "{}"))
    except json.JSONDecodeError as e:
        logger.warning(f"Ошибка парсинга JSON в inbound {inbound.get('id')}: {e}")
        return None

    # Для MTProto секрет обычно лежит в settings["secret"]
    secret = settings.get("secret")
    if not secret:
        logger.debug(f"Пропущен inbound {inbound.get('id')}: нет secret")
        return None

    # Порт берём из stream_settings или из общего поля port
    port = inbound.get("port")
    if not port:
        # иногда порт может быть в stream_settings
        port = stream_settings.get("port")
    if not port:
        logger.debug(f"Пропущен inbound {inbound.get('id')}: нет port")
        return None

    # Хост – обычно берётся из адреса панели, но в настройках может быть свой
    # Для TG прокси хост – это IP или домен, на котором работает панель
    host = SERVER_HOST  # используем хост панели (предполагаем, что прокси на том же сервере)
    # Если в inbound есть поле "listen" – можно взять его, но обычно игнорируем
    # Можно также попытаться взять из stream_settings["listen"]
    listen = stream_settings.get("listen")
    if listen and listen != "0.0.0.0":
        host = listen

    return {
        "host": host,
        "port": int(port),
        "secret": secret,
        "protocol": "mtproto",
    }

async def get_working_proxies() -> List[Dict[str, Any]]:
    """Получает список рабочих MTProto-прокси (проверяет доступность)."""
    async with aiohttp.ClientSession() as session:
        cookies = await get_panel_cookies(session)
        if not cookies:
            logger.error("Не удалось авторизоваться на панели")
            return []

        inbounds = await fetch_inbounds(session, cookies)
        if not inbounds:
            logger.error("Не удалось получить список inbound'ов")
            return []

        proxies = []
        for inbound in inbounds:
            proxy_info = extract_mtproto_proxy(inbound)
            if proxy_info:
                proxies.append(proxy_info)

        if not proxies:
            logger.warning("Не найдено ни одного MTProto-прокси")
            return []

        # Проверяем доступность параллельно
        logger.info(f"Начинаем проверку {len(proxies)} прокси...")
        check_tasks = [check_proxy(p["host"], p["port"]) for p in proxies]
        results = await asyncio.gather(*check_tasks)

        working = [p for p, ok in zip(proxies, results) if ok]
        logger.info(f"Найдено {len(working)} рабочих прокси из {len(proxies)}")
        return working

# ---------- Обработчики команд ----------
@dp.message(Command("start"))
async def cmd_start(message: types.Message):
    await message.answer(
        "👋 Привет! Я бот для выдачи прокси Telegram.\n"
        "Используй /getproxy – я дам тебе рабочий MTProto-прокси."
    )

@dp.message(Command("help"))
async def cmd_help(message: types.Message):
    await message.answer(
        "📖 Доступные команды:\n"
        "/getproxy – получить рабочий прокси (MTProto)\n"
        "/start – приветствие\n"
        "/help – эта справка"
    )

@dp.message(Command("getproxy"))
async def cmd_getproxy(message: types.Message):
    # Показываем статус
    status_msg = await message.answer("⏳ Ищу рабочий прокси...")

    try:
        proxies = await get_working_proxies()
    except Exception as e:
        logger.error(f"Ошибка при получении прокси: {e}")
        await status_msg.edit_text("❌ Не удалось получить список прокси из-за внутренней ошибки.")
        return

    if not proxies:
        await status_msg.edit_text("❌ В данный момент нет доступных рабочих прокси. Попробуйте позже.")
        return

    # Перемешиваем и берём первый
    random.shuffle(proxies)
    proxy = proxies[0]

    # Формируем ссылку tg://proxy
    tg_link = (
        f"https://t.me?"
        f"server={proxy['host']}"
        f"&port={proxy['port']}"
        f"&secret={proxy['secret']}"
    )
    if SPONSOR_TAG:
        tg_link += f"&tag={SPONSOR_TAG}"

    # Отвечаем пользователю
    await status_msg.edit_text(
        f"✅ Ваш прокси готов:\n"
        f"`{tg_link}`\n\n"
        f"🔒 Протокол: MTProto\n"
        f"🌐 Хост: {proxy['host']}\n"
        f"🔢 Порт: {proxy['port']}\n"
        f"🔑 Секрет: {proxy['secret'][:10]}... (скопируйте ссылку целиком)",
        parse_mode="Markdown"
    )

# ---------- Запуск ----------
if __name__ == "__main__":
    logger.info("Бот запускается...")
    dp.run_polling(bot)
