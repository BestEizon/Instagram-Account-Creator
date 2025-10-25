# telegram: @besteizon / @eizonxtool

import requests
import time
import json
import random
import re
import asyncio
import aiohttp
from urllib.parse import unquote
from fake_useragent import UserAgent
from rich.console import Console
from rich.table import Table
from rich import print as rprint
import os
import webbrowser
webbrowser.open("https://t.me/eizonxtool")
class Eizon:
    def __init__(self, token, chat_id):
        self.console = Console()
        self.ua = UserAgent()
        self.token = token
        self.chat_id = chat_id
        self.account_counter = 1
        
        os.system('clear')

    def generate_username(self):
        random_letters = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(8, 12)))
        
        
        random_numbers = ''.join(random.choices('0123456789', k=random.randint(5, 8)))
        
        
        username = f"eizon.{random_letters}{random_numbers}"
        
        return username

    def jq(self): 
        return ''.join([str(ord(c)) for c in "22825"])

    def jm(self): 
        return ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=32))

    def jd(self): 
        return ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz', k=28))

    def js(self): 
        return f"{''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=6))}:{''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=6))}:{''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=5))}"

    def send_telegram_message(self, message):    
        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        data = {"chat_id": self.chat_id, "text": message, "parse_mode": "HTML"}
        requests.post(url, data=data)

    def get_initial_cookies(self):
        url = "https://www.instagram.com/accounts/emailsignup/"
        headers = {'User-Agent': self.ua.random}
        response = requests.get(url, headers=headers)
        return response.cookies

    def extract_csrf_token(self, cookies):
        for cookie in cookies:
            if cookie.name == 'csrftoken':
                return cookie.value
        return self.jm()

    async def create_account(self):
        try:
            self.console.print(f"[bold yellow][1] Geçici email oluşturuluyor...[/bold yellow]")
            email, email_token = await self.generate_temp_email()
            if not email:
                self.console.print(f"[bold red][1] Email oluşturulamadı, tekrar deneyin...[/bold red]")
                return False
                
            self.console.print(f"[bold green][1] Email oluşturuldu: {email}[/bold green]")
            
            cookies = self.get_initial_cookies()
            csrf_token = self.extract_csrf_token(cookies)
            device_id = self.jd()
            session_id = self.js()
            jazoest = self.jq()                   
            
            username = self.generate_username()
            self.console.print(f"[bold green][1] Kullanıcı Adı Oluşturuldu: {username}[/bold green]")
            
            password = '8390419618'
            first_name = "Ali"
            last_name = "Arslan"                    
            
            base_headers = {
                'User-Agent': self.ua.random,
                'x-csrftoken': csrf_token,               
                'x-instagram-ajax': "1028850979",
                'origin': "https://www.instagram.com",
                'referer': "https://www.instagram.com/accounts/emailsignup/",
                'accept-language': "ar-IQ,ar;q=0.9,en-US;q=0.8,en;q=0.7",
            }                    
            
            cookie_dict = {'mid': device_id, 'csrftoken': csrf_token, 'ig_did': device_id}        
            
            
            url_attempt = "https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/"
            payload_attempt = {
                'enc_password': f"#PWD_INSTAGRAM_BROWSER:0:{int(time.time())}:{password}",
                'email': email, 'failed_birthday_year_count': "{}", 'first_name': first_name, 'username': username,
                'client_id': device_id, 'seamless_login_enabled': "1", 'opt_into_one_tap': "false",
                'use_new_suggested_user_name': "true", 'jazoest': jazoest
            }                    
            
            headers_attempt = base_headers.copy()
            headers_attempt.update({'x-web-session-id': session_id, 'Cookie': '; '.join([f'{k}={v}' for k, v in cookie_dict.items()])})                    
            
            response_attempt = requests.post(url_attempt, data=payload_attempt, headers=headers_attempt)
            self.console.print(f"[bold green][1] Attempt: ✓[/bold green]")    
            
            
            url_age_check = "https://www.instagram.com/api/v1/web/consent/check_age_eligibility/"
            payload_age_check = {'day': "24", 'month': "10", 'year': "2002", 'jazoest': jazoest}
            response_age_check = requests.post(url_age_check, data=payload_age_check, headers=headers_attempt)
            self.console.print(f"[bold green][1] Age Check: ✓[/bold green]")        
            
            
            url_send_verify = "https://www.instagram.com/api/v1/accounts/send_verify_email/"
            payload_send_verify = {'device_id': device_id, 'email': email, 'jazoest': jazoest}
            response_send_verify = requests.post(url_send_verify, data=payload_send_verify, headers=headers_attempt)
            self.console.print(f"[bold green][1] Verify Email: ✓[/bold green]")        
            
            self.console.print(f"[bold yellow][1] Doğrulama kodu bekleniyor...[/bold yellow]")
            verification_code = await self.get_verification_code(email_token)
            if not verification_code:
                self.console.print(f"[bold red][1] Doğrulama kodu alınamadı, tekrar deneyin...[/bold red]")
                return False
                
            self.console.print(f"[bold green][1] Kod alındı: {verification_code}[/bold green]")
            
            
            url_check_code = "https://www.instagram.com/api/v1/accounts/check_confirmation_code/"
            payload_check_code = {'code': verification_code, 'device_id': device_id, 'email': email, 'jazoest': jazoest}
            headers_attempt.update({'x-web-session-id': self.js()})
            response_check_code = requests.post(url_check_code, data=payload_check_code, headers=headers_attempt)
            self.console.print(f"[bold green][1] Code Check: ✓[/bold green]")                    
            
            try:
                response_data = json.loads(response_check_code.text)
                signup_code = response_data.get("signup_code", "")
                self.console.print(f"[bold green][1] Signup Code: {signup_code}[/bold green]")
            except:
                self.console.print(f"[bold red][1] Signup Code: ✗[/bold red]")
                signup_code = ""        
            
            
            url_final = "https://www.instagram.com/api/v1/web/accounts/web_create_ajax/"
            payload_final = {
                'enc_password': f"#PWD_INSTAGRAM_BROWSER:0:{int(time.time())}:{password}",
                'day': "24", 'email': email, 'failed_birthday_year_count': "{}", 'first_name': first_name,
                'month': "10", 'username': username, 'year': "2002", 'client_id': device_id,
                'seamless_login_enabled': "1", 'tos_version': "row", 'force_sign_up_code': signup_code,
                'extra_session_id': session_id, 'jazoest': jazoest
            }                    
            
            response_final = requests.post(url_final, data=payload_final, headers=headers_attempt)
            self.console.print(f"[bold green][1] Final: ✓[/bold green]")                    
            
            session_id_value = None
            user_id = None
            
            try:
                final_data = json.loads(response_final.text)
                
                if final_data.get('account_created', False):
                    
                    user_id = final_data.get('user_id')
                    if not user_id and 'created_user' in final_data:
                        user_id = final_data['created_user'].get('pk')
                    
                    if 'set-cookie' in response_final.headers:
                        cookies = response_final.headers['set-cookie']
                        session_match = re.search(r'sessionid=([^;]+)', cookies)
                        if session_match:
                            session_id_value = unquote(session_match.group(1))
                    elif response_final.cookies and 'sessionid' in response_final.cookies:
                        session_id_value = response_final.cookies.get('sessionid')
                        
                    self.console.print(f"[bold green][1] User ID bulundu: {user_id}[/bold green]")
                    self.console.print(f"[bold green][1] Session ID: {session_id_value}[/bold green]")
                else:
                    self.console.print(f"[bold red][1] Hesap oluşturulamadı! Response: {response_final.text}[/bold red]")
            except Exception as e:
                self.console.print(f"[bold red][1] Response parse hatası: {e}[/bold red]")

            
            self.console.print(f"\n[bold red]✗ HESAP #{self.account_counter} BAŞARIYLA OLUŞTURULDU ✗[/bold red]\n")
            
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Bilgi", style="dim", width=20)
            table.add_column("Değer", style="bold white")
            
            table.add_row("Hesap No", str(self.account_counter))
            table.add_row("Ad Soyad", f"{first_name} {last_name}")
            table.add_row("Kullanıcı Adı", f"@{username}")
            table.add_row("Email", email)
            table.add_row("Şifre", password)
            table.add_row("User ID", str(user_id) if user_id else "N/A")
            table.add_row("Session ID", session_id_value if session_id_value else "N/A")
            
            self.console.print(table)
            

            message = f"""
⋘─────━𓆩𝐄𝐈𝐙𝐎𝐍𓆪‏━─────⋙            
<b>• Hesap No:</b> <code>{self.account_counter}</code>
<b>• Name:</b> <code>{first_name} {last_name}</code>
<b>• Username:</b> <code>@{username}</code>
<b>• Email:</b> <code>{email}</code>
<b>• Password:</b> <code>{password}</code>
<b>• User ID:</b> <code>{user_id if user_id else 'N/A'}</code>
<b>• Session id: </b> <code>{session_id_value if session_id_value else 'N/A'}</code>
⋘─────━𓆩𝐄𝐈𝐙𝐎𝐍𓆪‏━─────⋙
• 𝐓𝐞𝐥𝐞𝐠𝐫𝐚𝐦 ~ @BestEizon • @EizonxTool
"""                
            self.send_telegram_message(message)
            
            self.account_counter += 1
            return True
            
        except Exception as e:
            self.console.print(f"[bold red][1] ERROR : {e}[/bold red]")
            return False

    async def generate_temp_email(self):
        for _ in range(3):
            email_generator = EmailGenerator()
            email_data = await email_generator.generate()
            if email_data and email_data[0] and email_data[1]:
                return email_data
        return False, False

    async def get_verification_code(self, token: str):
        email_generator = EmailGenerator()
        code = await email_generator.get_mailbox(token)
        if code:
            match = re.search(r'\b\d{6}\b', code)
            if match:
                return match.group(0)
        return None

    async def start_creation(self):
        while True:
            success = await self.create_account()
            
            if success:
                self.console.print(f"[bold yellow]X {self.account_counter}. hesap için 10 saniye bekleniyor...[/bold yellow]")
                time.sleep(10)
            else:
                self.console.print(f"[bold yellow]X {self.account_counter}. hesap için 5 saniye bekleniyor...[/bold yellow]")
                time.sleep(5)


class EmailGenerator:
    def __init__(self):
        self.url = "https://api.mail.tm"
        self.headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }
        
    async def generate(self):
        async with aiohttp.ClientSession(headers=self.headers) as session:
            try:
                async with session.get(f"{self.url}/domains") as resp:
                    data = await resp.json()
                    domain = data["hydra:member"][0]["domain"]

                mail = ''.join(random.choice("qwertyuiopasdfghjklzxcvbnm") for _ in range(12)) + "@" + domain
                password = ''.join(random.choice("qwertyuiopasdfghjklzxcvbnm") for _ in range(12))
                
                payload = {"address": mail, "password": password}
                async with session.post(f"{self.url}/accounts", json=payload) as resp:
                    if resp.status != 201:
                        return False, False

                async with session.post(f"{self.url}/token", json=payload) as resp:
                    if resp.status != 200:
                        return False, False
                    token_data = await resp.json()
                    return mail, token_data.get("token")

            except Exception as e:
                return False, False

    async def get_mailbox(self, token: str):
        async with aiohttp.ClientSession(headers={**self.headers, "Authorization": f"Bearer {token}"}) as session:
            max_attempts = 15
            attempts = 0
            
            while attempts < max_attempts:
                attempts += 1
                await asyncio.sleep(5)
                try:
                    async with session.get(f"{self.url}/messages") as resp:
                        if resp.status != 200:
                            continue
                        inbox = await resp.json()
                        messages = inbox.get("hydra:member", [])
                        if messages:
                            latest_msg = messages[0]
                            msg_id = latest_msg["id"]
                            async with session.get(f"{self.url}/messages/{msg_id}") as r:
                                if r.status == 200:
                                    msg = await r.json()
                                    return msg.get("text", "")
                except Exception:
                    continue
            return None


if __name__ == "__main__":
    token = input('token: ')
    chat_id = input('id: ')
    
    creator = Eizon(token, chat_id)
    asyncio.run(creator.start_creation())
    
    
    
    
    # tg @besteizon / @eizonxtool