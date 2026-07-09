import os
import json
import random
import asyncio
import aiohttp
from dotenv import load_dotenv
from aiogram import Bot, Dispatcher, types
from aiogram.filters import CommandStart
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton

# Загружаем переменные окружения из файла .env
load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
SPONSOR_TAG = os.getenv("SPONSOR_TAG")
PANEL_URL = os.getenv("PANEL_URL")        # Формат: http://12.34.56.78:2053
PANEL_LOGIN = os.getenv("PANEL_LOGIN")
PANEL_PASSWORD = os.getenv("PANEL_PASSWORD")

# Валидация наличия критически важных переменных
if not all([BOT_TOKEN, PANEL_URL, PANEL_LOGIN, PANEL_PASSWORD]):
    raise ValueError("Критические переменные окружения отсутствуют в файле .env! Проверьте конфигурацию.")

# Безопасно извлекаем чистый IP-адрес/хост сервера для работы чекера портов
# Удаляет протокол 'http://', порт ':2053' и возможные слеши
SERVER_HOST = PANEL_URL.split("//")[-1].split(":")[0].replace("/", "")

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

async def get_proxies_from_panel():
    """Автоматически авторизуется в 3x-ui и собирает актуальные прокси-конфигурации через API"""
    proxies_list = []
    login_url = f"{PANEL_URL}/login"
    api_url = f"{PANEL_URL}/panel/api/inbounds/list"
    
    # Использование ClientSession критично: объект автоматически сохраняет сессионные Cookie авторизации
    async with aiohttp.ClientSession() as session:
        try:
            # 1. Авторизация в панели 3x-ui
            credentials = {"username": PANEL_LOGIN, "password": PANEL_PASSWORD}
            async with session.post(login_url, data=credentials, timeout=5) as resp:
                if resp.status != 200:
                    print("[Ошибка 3x-ui API]: Не удалось авторизоваться. Проверьте логин/пароль в .env.")
                    return proxies_list
            
            # 2. Получение списка входящих подключений (Inbounds)
            async with session.get(api_url, timeout=5) as resp:
                if resp.status == 200:
                    json_data = await resp.json()
                    if json_data.get("success"):
                        
                        for item in json_data.get("obj", []):
                            protocol = item.get("protocol")
                            port = item.get("port")
                            
                            # Парсинг нативного MTProto прокси
                            if protocol == "mtproto":
                                settings = json.loads(item.get("settings", "{}"))
                                users = settings.get("users", [])
                                if users and len(users) > 0:
                                    # В 3x-ui users — это список. Берем секрет первого пользователя.
                                    secret = users[0].get("secret", "")
                                    if secret:
                                        proxies_list.append({
                                            "type": "mtproto",
                                            "server": SERVER_HOST,
                                            "port": port,
                                            "secret": secret
                                        })
                                        
                            # Парсинг VLESS Reality
                            elif protocol == "vless":
                                settings = json.loads(item.get("settings", "{}"))
                                stream_settings = json.loads(item.get("streamSettings", "{}"))
                                clients = settings.get("clients", [])
                                
                                if clients and len(clients) > 0 and stream_settings.get("security") == "reality":
                                    client_id = clients[0].get("id", "")
                                    reality_settings = stream_settings.get("realitySettings", {})
                                    
                                    # Извлекаем параметры маскировки Reality
                                    sni_list = reality_settings.get("serverNames", [""])
                                    sni = sni_list[0] if sni_list else ""
                                    pbk = reality_settings.get("publicKey", "")
                                    short_ids = reality_settings.get("shortIds", [""])
                                    short_id = short_ids[0] if short_ids else ""
                                    
                                    # Формируем стандартный URI для VLESS Reality клиента
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
            print(f"[Критическое исключение при запросе к панели]: {e}")
            
    return proxies_list

async def check_proxy_ping(host, port):
    """Асинхронный чекер: проверяет доступность TCP-порта сервера перед выдачей ссылки пользователю"""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, int(port)), timeout=1.5
        )
        writer.close()
        await writer.wait_closed()
        return True
    except:
        return False

@dp.message(CommandStart())
async def cmd_start(message: types.Message):
    await message.answer("🔄 Подключаюсь к панели управления серверами, проверяю статус прокси...")
    
    # Бот на лету запрашивает актуальные прокси из панели
    all_proxies = await get_proxies_from_panel()
    if not all_proxies:
        await message.answer("⚠️ База данных прокси временно недоступна или пуста. Администратор уже уведомлен.")
        return

    # Перемешиваем список, чтобы распределять нагрузку на разные порты/прокси
    random.shuffle(all_proxies)
    
    mtproto_proxy = None
    vless_proxy = None
    
    # Ищем первый рабочий MTProto и первый доступный VLESS
    for proxy in all_proxies:
        if proxy["type"] == "mtproto":
            if await check_proxy_ping(proxy["server"], proxy["port"]):
                mtproto_proxy = proxy
                break
        elif proxy["type"] == "vless":
            vless_proxy = proxy

    # Если найден активный MTProto с поддержкой спонсорского канала
    if mtproto_proxy:
        tg_proxy_url = (
            f"https://t.me?"
            f"server={mtproto_proxy['server']}&"
            f"port={mtproto_proxy['port']}&"
            f"secret={mtproto_proxy['secret']}"
        )
        # Если в .env указан рекламный тег канала, добавляем его в ссылку
        if SPONSOR_TAG:
            tg_proxy_url += f"&tag={SPONSOR_TAG}"
        
        kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="⚡️ ПОДКЛЮЧИТЬ ПРОКСИ В 1 КЛИК", url=tg_proxy_url)]
        ])
        
        text = (
            "🤖 **Индивидуальный MTProto прокси успешно подобран!**\n\n"
            "Нажмите кнопку ниже, чтобы применить конфигурацию ко всему вашему приложению Telegram.\n\n"
            "Дополнительное ПО не требуется. Наверху списка чатов появится закрепленный спонсорский канал."
        )
        
        if vless_proxy:
            text += f"\n\n🔗 **Резервный ключ VLESS Reality (для сторонних приложений v2ray/Xray):**\n`{vless_proxy['url']}`"
            
        await message.answer(text, reply_markup=kb, parse_mode="Markdown")
    else:
        await message.answer("❌ Свободные MTProto прокси сейчас перегружены. Пожалуйста, повторите попытку через минуту.")

async def main():
    print(f"[Запуск]: Бот успешно стартовал. Целевой хост синхронизации: {SERVER_HOST}")
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
