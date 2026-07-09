import os
import json
import random
import asyncio
import aiohttp
from dotenv import load_dotenv
from aiogram import Bot, Dispatcher, types
from aiogram.filters import CommandStart
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton

# Загружаем скрытые переменные окружения
load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
SPONSOR_TAG = os.getenv("SPONSOR_TAG")
PANEL_URL = os.getenv("PANEL_URL")        # Формат: http://12.34.56.78:2053
PANEL_LOGIN = os.getenv("PANEL_LOGIN")
PANEL_PASSWORD = os.getenv("PANEL_PASSWORD")

# Чистим базовый IP сервера для чекера и сборщика ссылок
SERVER_IP = PANEL_URL.split("//")[-1].split(":")[0]

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

async def get_proxies_from_panel():
    """Синхронизируется с API 3x-ui и собирает актуальные протоколы"""
    proxies_list = []
    login_url = f"{PANEL_URL}/login"
    api_url = f"{PANEL_URL}/panel/api/inbounds/list"
    
    # ClientSession автоматически сохраняет Cookie авторизации для последующих запросов
    async with aiohttp.ClientSession() as session:
        try:
            # 1. Авторизация на панели
            credentials = {"username": PANEL_LOGIN, "password": PANEL_PASSWORD}
            async with session.post(login_url, data=credentials, timeout=5) as resp:
                if resp.status != 200:
                    print("[Ошибка API]: Неверные данные авторизации или панель недоступна.")
                    return proxies_list
            
            # 2. Получение списка прокси
            async with session.get(api_url, timeout=5) as resp:
                if resp.status == 200:
                    json_data = await resp.json()
                    if json_data.get("success"):
                        
                        for item in json_data.get("obj", []):
                            protocol = item.get("protocol")
                            port = item.get("port")
                            
                            # Обработка нативного MTProto
                            if protocol == "mtproto":
                                settings = json.loads(item.get("settings", "{}"))
                                users = settings.get("users", [])
                                if users:
                                    secret = users[0].get("secret", "")
                                    if secret:
                                        proxies_list.append({
                                            "type": "mtproto",
                                            "server": SERVER_IP,
                                            "port": port,
                                            "secret": secret
                                        })
                                        
                            # Обработка VLESS Reality
                            elif protocol == "vless":
                                settings = json.loads(item.get("settings", "{}"))
                                stream_settings = json.loads(item.get("streamSettings", "{}"))
                                clients = settings.get("clients", [])
                                
                                if clients and stream_settings.get("security") == "reality":
                                    client_id = clients[0].get("id", "")
                                    reality_settings = stream_settings.get("realitySettings", {})
                                    sni = reality_settings.get("serverNames", [""])[0]
                                    pbk = reality_settings.get("publicKey", "")
                                    short_id = reality_settings.get("shortIds", [""])[0]
                                    
                                    vless_url = (
                                        f"vless://{client_id}@{SERVER_IP}:{port}?"
                                        f"security=reality&encryption=none&pbk={pbk}&"
                                        f"headerType=none&fp=chrome&type=tcp&sni={sni}&sid={short_id}#FastProxy"
                                    )
                                    proxies_list.append({
                                        "type": "vless",
                                        "url": vless_url
                                    })
        except Exception as e:
            print(f"[Критическая ошибка API панели]: {e}")
            
    return proxies_list

async def check_proxy_ping(ip, port):
    """Асинхронно тестирует TCP-порт прокси на доступность перед выдачей"""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, int(port)), timeout=1.5
        )
        writer.close()
        await writer.wait_closed()
        return True
    except:
        return False

@dp.message(CommandStart())
async def cmd_start(message: types.Message):
    await message.answer("🔄 Подключаюсь к кластеру серверов, проверяю статус прокси...")
    
    all_proxies = await get_proxies_from_panel()
    if not all_proxies:
        await message.answer("⚠️ База данных прокси пуста или сервер обновляется. Попробуйте позже.")
        return

    random.shuffle(all_proxies)
    
    mtproto_proxy = None
    vless_proxy = None
    
    for proxy in all_proxies:
        if proxy["type"] == "mtproto":
            # Передаем атомарные строковые и числовые типы, а не списки
            if await check_proxy_ping(proxy["server"], proxy["port"]):
                mtproto_proxy = proxy
                break
        elif proxy["type"] == "vless":
            vless_proxy = proxy

    if mtproto_proxy:
        tg_proxy_url = (
            f"https://t.me?"
            f"server={mtproto_proxy['server']}&"
            f"port={mtproto_proxy['port']}&"
            f"secret={mtproto_proxy['secret']}"
        )
        if SPONSOR_TAG:
            tg_proxy_url += f"&tag={SPONSOR_TAG}"
        
        kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="⚡️ ПОДКЛЮЧИТЬ В 1 НАЖАТИЕ", url=tg_proxy_url)]
        ])
        
        text = (
            "🤖 **Индивидуальный прокси подобран!**\n\n"
            "Нажмите кнопку ниже, чтобы применить конфигурацию ко всему приложению Telegram. Дополнительное ПО не требуется."
        )
        if vless_proxy:
            text += f"\n\n🔗 **Резервный ключ VLESS (для сторонних клиентов):**\n`{vless_proxy['url']}`"
            
        await message.answer(text, reply_markup=kb, parse_mode="Markdown")
    else:
        await message.answer("❌ На сервере ведутся технические работы. Пожалуйста, повторите попытку через минуту.")

async def main():
    print(f"[Система]: Бот инициализирован. Целевой IP панели: {SERVER_IP}")
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
