import os
import json
import random
import asyncio
import logging
import aiohttp
from dotenv import load_dotenv
from aiogram import Bot, Dispatcher, types
from aiogram.filters import CommandStart, Command
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton

# Настраиваем детальное логирование в консоль
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Загружаем скрытые переменные из файла .env
load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
SPONSOR_TAG = os.getenv("SPONSOR_TAG", "")
PANEL_URL = os.getenv("PANEL_URL")        # Формат: http://12.34.56.78:2053
PANEL_LOGIN = os.getenv("PANEL_LOGIN")
PANEL_PASSWORD = os.getenv("PANEL_PASSWORD")

# Строгая проверка конфигурации перед запуском
if not all([BOT_TOKEN, PANEL_URL, PANEL_LOGIN, PANEL_PASSWORD]):
    logger.critical("Критические переменные окружения отсутствуют в файле .env!")
    raise ValueError("Проверьте конфигурацию вашего .env файла.")

# Очищаем PANEL_URL от слешей на конце и извлекаем чистый IP/хост для чекера портов
BASE_URL = PANEL_URL.rstrip("/")
SERVER_HOST = BASE_URL.split("//")[-1].split(":")[0]

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

async def get_proxies_from_panel():
    """
    Авторизуется в 3x-ui через официальный эндпоинт /login, 
    сохраняет Cookie и забирает список прокси из /panel/api/inbounds/list
    """
    proxies_list = []
    login_url = f"{BASE_URL}/login"
    api_url = f"{BASE_URL}/panel/api/inbounds/list"
    
    # Используем одну сессию aiohttp, чтобы Cookie авторизации автоматически прокидывались в API
    async with aiohttp.ClientSession() as session:
        try:
            # 1. Отправляем запрос на авторизацию (Эндпоинт: /login)
            credentials = {"username": PANEL_LOGIN, "password": PANEL_PASSWORD}
            async with session.post(login_url, data=credentials, timeout=5) as resp:
                if resp.status != 200:
                    logger.error("Ошибка авторизации в 3x-ui. Проверьте PANEL_LOGIN и PANEL_PASSWORD.")
                    return proxies_list
                
            # 2. Запрашиваем список всех прокси (Эндпоинт: /panel/api/inbounds/list)
            async with session.get(api_url, timeout=5) as resp:
                if resp.status != 200:
                    logger.error(f"Панель вернула ошибку HTTP {resp.status} на запрос списка прокси.")
                    return proxies_list
                
                json_data = await resp.json()
                if not json_data.get("success"):
                    logger.error("API панели вернуло success: false.")
                    return proxies_list
                
                # Начинаем парсинг объектов (Inbounds)
                for item in json_data.get("obj", []):
                    if not item.get("enable"):  # Пропускаем выключенные в панели прокси
                        continue
                        
                    protocol = item.get("protocol")
                    port = item.get("port")
                    
                    # Разбираем нативный MTProto
                    if protocol == "mtproto":
                        settings = json.loads(item.get("settings", "{}"))
                        users = settings.get("users", [])
                        if users and len(users) > 0:
                            secret = users[0].get("secret", "")
                            if secret:
                                proxies_list.append({
                                    "type": "mtproto",
                                    "server": SERVER_HOST,
                                    "port": port,
                                    "secret": secret
                                })
                                
                    # Разбираем VLESS Reality
                    elif protocol == "vless":
                        settings = json.loads(item.get("settings", "{}"))
                        stream_settings = json.loads(item.get("streamSettings", "{}"))
                        clients = settings.get("clients", [])
                        
                        if clients and len(clients) > 0 and stream_settings.get("security") == "reality":
                            client_id = clients[0].get("id", "")
                            reality_settings = stream_settings.get("realitySettings", {})
                            
                            sni_list = reality_settings.get("serverNames", [""])
                            sni = sni_list[0] if sni_list else ""
                            pbk = reality_settings.get("publicKey", "")
                            short_ids = reality_settings.get("shortIds", [""])
                            short_id = short_ids[0] if short_ids else ""
                            
                            # Собираем бесшовную VLESS строку без лишних пробелов
                            vless_url = (
                                f"vless://{client_id}@{SERVER_HOST}:{port}?"
                                f"security=reality&encryption=none&pbk={pbk}&"
                                f"headerType=none&fp=chrome&type=tcp&sni={sni}&sid={short_id}#FastProxy"
                            )
                            proxies_list.append({
                                "type": "vless",
                                "url": vless_url
                            })
                            
        except Exception as e:
            logger.error(f"Исключение при работе с API панели 3x-ui: {e}")
            
    return proxies_list
async def check_proxy_ping(host: str, port: int) -> bool:
    """
    Асинхронный TCP-чекер: пытается открыть сетевое соединение с портом сервера.
    Защищает пользователей от получения неработающих или "упавших" прокси.
    """
    try:
        # Устанавливаем соединение с таймаутом 1.5 секунды, чтобы бот не зависал
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, int(port)), timeout=1.5
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False

@dp.message(CommandStart())
async def cmd_start(message: types.Message):
    """Обработчик команды /start с приветствием и кнопкой запроса прокси"""
    welcome_text = (
        f"👋 Привет, {message.from_user.first_name}!\n\n"
        "🤖 Я официальный бот для быстрой выдачи стабильных прокси.\n"
        "Синхронизация с серверами происходит автоматически в реальном времени.\n\n"
        "Чтобы получить самый быстрый прокси, нажмите кнопку ниже или введите команду /getproxy."
    )
    
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="⚡️ ПОЛУЧИТЬ ПРОКСИ", callback_data="request_proxy")]
    ])
    
    await message.answer(welcome_text, reply_markup=kb)

@dp.message(Command("getproxy"))
@dp.callback_query(lambda c: c.data == "request_proxy")
async def handle_proxy_request(event: types.Message | types.CallbackQuery):
    """
    Основная логика: запрашивает данные из панели 3x-ui, выбирает случайный 
    рабочий MTProto прокси и генерирует нативную ссылку со спонсорским тегом.
    """
    # Определяем, откуда пришел запрос — из текста или от нажатия кнопки
    is_callback = isinstance(event, types.CallbackQuery)
    message = event.message if is_callback else event

    if is_callback:
        await event.answer("🔄 Подбираю прокси...")
        # Обновляем текст сообщения, показывая загрузку
        await message.text("🔄 Подключаюсь к панели серверов, проверяю статус прокси...")

    else:
        await message.answer("🔄 Подключаюсь к панели серверов, проверяю статус прокси...")

    # Получаем свежий список прокси напрямую из API 3x-ui
    all_proxies = await get_proxies_from_panel()
    
    if not all_proxies:
        error_text = "⚠️ База данных прокси временно недоступна или пуста. Администратор уже уведомлен."
        await message.answer(error_text)
        return

    # Перемешиваем список, чтобы распределять нагрузку на разные прокси равномерно
    random.shuffle(all_proxies)
    
    mtproto_proxy = None
    vless_proxy = None
    
    # Ищем первый рабочий MTProto (пропуская через чекер) и первый доступный VLESS
    for proxy in all_proxies:
        if proxy["type"] == "mtproto" and not mtproto_proxy:
            if await check_proxy_ping(proxy["server"], proxy["port"]):
                mtproto_proxy = proxy
                # Если VLESS уже найден, можно досрочно выйти из цикла
                if vless_proxy:
                    break
        elif proxy["type"] == "vless" and not vless_proxy:
            vless_proxy = proxy

    # Если нашли рабочий MTProto прокси
    if mtproto_proxy:
        # Важно: Формируем именно универсальную HTTPS ссылку t.me/proxy
        tg_proxy_url = (
            f"https://t.me?"
            f"server={mtproto_proxy['server']}&"
            f"port={mtproto_proxy['port']}&"
            f"secret={mtproto_proxy['secret']}"
        )
        
        # Если в .env задан Proxy Tag спонсорского канала, прикрепляем его к ссылке
        if SPONSOR_TAG:
            tg_proxy_url += f"&tag={SPONSOR_TAG}"
        
        kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="⚡️ ПОДКЛЮЧИТЬ ПРОКСИ В 1 КЛИК", url=tg_proxy_url)]
        ])
        
        success_text = (
            "🤖 **Ваш персональный прокси успешно подобран!**\n\n"
            "Просто нажмите кнопку ниже. Telegram автоматически применит настройки "
            "и подключит вас к защищенной сети.\n\n"
            "Никаких сторонних программ не требуется. Наверху списка чатов появится "
            "ваш спонсорский канал."
        )
        
        # Если на сервере также поднят VLESS Reality, отдаем его текстом в качестве резерва
        if vless_proxy:
            success_text += (
                f"\n\n🔗 **Резервный ключ VLESS Reality** (для сквозного обхода блокировок "
                f"всего интернета через сторонние утилиты v2rayNG/Amnezia/v2rayN):\n"
                f"`{vless_proxy['url']}`"
            )
            
        await message.answer(success_text, reply_markup=kb, parse_mode="Markdown")
        
    else:
        # Если все прокси упали или пинг не прошел
        await message.answer(
            "❌ Все MTProto прокси сейчас перегружены или недоступны.\n"
            "Пожалуйста, повторите попытку через минуту, система автоматически перезапускает протоколы."
        )

async def main():
    logger.info(f"Бот успешно инициализирован. Целевой хост панели 3x-ui: {SERVER_HOST}")
    # Запускаем бесконечный опрос серверов Telegram (Long Polling)
    await dp.start_polling(bot)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        logger.info("Бот успешно остановлен.")
