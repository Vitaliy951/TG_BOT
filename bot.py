import asyncio
import random
import aiohttp
from aiogram import Bot, Dispatcher, types
from aiogram.filters import CommandStart
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton

# --- НАСТРОЙКИ ---
BOT_TOKEN = "ВАШ_ТОКЕН_ОТ_BOT_FATHER"
SPONSOR_TAG = "ТЕГ_ИЗ_MTPROXYBOT"  # Ваш Proxy Tag, полученный от @MTProxybot для спонсорского канала

# Настройки подключения к вашей панели 3x-ui
PANEL_URL = "http://IP_ВАШЕГО_СЕРВЕРА:2053" 
PANEL_LOGIN = "ВАШ_ЛОГИН_ОТ_ПАНЕЛИ"
PANEL_PASSWORD = "ВАШ_ПАРОЛЬ_ОТ_ПАНЕЛИ"

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

async def get_proxies_from_panel():
    """Автоматически подключается к 3x-ui и забирает список рабочих прокси"""
    proxies_list = []
    login_url = f"{PANEL_URL}/login"
    api_url = f"{PANEL_URL}/panel/api/inbounds/list"
    
    # Используем aiohttp сессию с куками для авторизации в панели
    async with aiohttp.ClientSession() as session:
        try:
            # 1. Логинимся в панель
            data = {"username": PANEL_LOGIN, "password": PANEL_PASSWORD}
            async with session.post(login_url, data=data, timeout=5) as resp:
                if resp.status != 200:
                    print("Ошибка авторизации в панели 3x-ui")
                    return proxies_list
            
            # 2. Запрашиваем список всех подключений (Inbounds)
            async with session.get(api_url, timeout=5) as resp:
                if resp.status == 200:
                    json_data = await resp.json()
                    if json_data.get("success"):
                        # Фильтруем и собираем прокси
                        for item in json_data.get("obj", []):
                            # Извлекаем IP сервера из URL панели
                            server_ip = PANEL_URL.split("//")[-1].split(":")[0]
                            port = item.get("port")
                            
                            # Если это MTProto прокси
                            if item.get("protocol") == "mtproto":
                                # Парсим секрет из настроек
                                import json
                                settings = json.loads(item.get("settings", "{}"))
                                secret = settings.get("users", [{}])[0].get("secret", "")
                                if secret:
                                    proxies_list.append({
                                        "type": "mtproto",
                                        "server": server_ip,
                                        "port": port,
                                        "secret": secret
                                    })
                                    
                            # Если это VLESS Reality (для выдачи ссылки текстом)
                            elif item.get("protocol") == "vless":
                                import json
                                stream_settings = json.loads(item.get("streamSettings", "{}"))
                                settings = json.loads(item.get("settings", "{}"))
                                client_id = settings.get("clients", [{}])[0].get("id", "")
                                
                                if stream_settings.get("security") == "reality":
                                    reality_settings = stream_settings.get("realitySettings", {})
                                    sni = reality_settings.get("serverNames", [""])[0]
                                    pbk = reality_settings.get("publicKey", "")
                                    short_id = reality_settings.get("shortIds", [""])[0]
                                    
                                    # Формируем стандартную ссылку VLESS Reality
                                    vless_url = f"vless://{client_id}@{server_ip}:{port}?security=reality&encryption=none&pbk={pbk}&headerType=none&fp=chrome&spx=%2F&type=tcp&sni={sni}&sid={short_id}#FastProxy"
                                    proxies_list.append({
                                        "type": "vless",
                                        "url": vless_url
                                    })
        except Exception as e:
            print(f"Ошибка при работе с API панели: {e}")
            
    return proxies_list

async def check_proxy_ping(ip, port):
    """Быстрый асинхронный чекер доступности порта сервера"""
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
    await message.answer("🔄 Связываюсь с сервером, подбираю лучший прокси...")
    
    # Бот сам идет в панель за свежими данными
    all_proxies = await get_proxies_from_panel()
    
    if not all_proxies:
        await message.answer("⚠️ Сервер временно недоступен или список прокси пуст.")
        return

    # Перемешиваем для балансировки нагрузки
    random.shuffle(all_proxies)
    
    mtproto_proxy = None
    vless_proxy = None
    
    # Ищем первый рабочий MTProto (проверяя пинг) и первый VLESS
    for proxy in all_proxies:
        if proxy["type"] == "mtproto":
            if await check_proxy_ping(proxy["server"], proxy["port"]):
                mtproto_proxy = proxy
                break
        elif proxy["type"] == "vless":
            vless_proxy = proxy

    # Если нашли рабочий MTProto с рекламой
    if mtproto_proxy:
        # Автоматически собираем ссылку с вашим SPONSOR_TAG
        tg_proxy_url = (
            f"https://t.me?"
            f"server={mtproto_proxy['server']}&"
            f"port={mtproto_proxy['port']}&"
            f"secret={mtproto_proxy['secret']}&"
            f"tag={SPONSOR_TAG}"
        )
        
        kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="⚡️ ПОДКЛЮЧИТЬ В 1 КЛИК", url=tg_proxy_url)]
        ])
        
        text = (
            "🤖 **Прокси успешно получен напрямую с сервера!**\n\n"
            "Нажмите кнопку ниже. Telegram применит настройки автоматически. Наверху появится ваш спонсорский канал."
        )
        
        # Дополнительно даем VLESS ссылку, если она есть (как резерв для обхода жестких блокировок)
        if vless_proxy:
            text += f"\n\n🔗 **Резервный VLESS (для сторонних приложений типа V2rayNG/AnXray):**\n`{vless_proxy['url']}`"
            
        await message.answer(text, reply_markup=kb, parse_mode="Markdown")
    else:
        await message.answer("❌ Рабочих MTProto прокси сейчас нет, попробуйте через пару минут.")

async def main():
    print("Бот запущен и автоматически синхронизирован с панелью 3x-ui!")
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
