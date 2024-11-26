"""
  - Copyright 2024 Ruri Gokou (Kuroneko-yousenpai)
  - Email: Kuronekoyousenpai@gmail.com
  - Telegram: https://t.me/Kuroneko_yousenpai
  - VK: https://vk.com/kuroneko_yousenpai
"""

import asyncio
import json
from aiohttp import web
from loguru import logger


@web.middleware
async def server_header_middleware(request, handler):
    try:
        response = await handler(request)
    except web.HTTPException as ex:
        response = ex
    if "Server" in response.headers:
        if "aiohttp" in response.headers["Server"]:
            response.headers["Server"] = "nginx"
    return response

@web.middleware
async def server_errors_middleware(request, handler):
    try:
        try:
            response = await handler(request)
        except web.HTTPMethodNotAllowed:
            raise web.HTTPNotFound(reason="Not Found")
    except web.HTTPException as ex:
        response = ex
    if "Server" in response.headers:
        if "aiohttp" in response.headers["Server"]:
            response.headers["Server"] = "nginx"
    return response

class WormixHTTPServer:
    def __init__(self, server_type):
        self.server_type = server_type

    async def handle_get(self, request: web.Request) -> web.StreamResponse:
        r_addr = request.remote
        logger.debug(f"({self.server_type}) (port {WmxHttpServer.HTTP_PORT}) [{r_addr}] Request: {request.url}")
        if request.path == "/crossdomain.xml":
            cross_domain_policy = """
                <?xml version="1.0"?>
                <cross-domain-policy>
                 <site-control permitted-cross-domain-policies="master-only"/>
                 <allow-http-request-headers-from domain="*" headers="*"/>
                 <allow-access-from domain="*" to-ports="*" secure="false"/>
                </cross-domain-policy>
                
            """
            headers = {"Content-Type": "text/xml"}
            logger.debug(f"({self.server_type}) (port {WmxHttpServer.HTTP_PORT}) [{r_addr}] Policy file sended!")
            return web.Response(text=cross_domain_policy, headers=headers)
        elif "platform" in request.path: # MM api
            headers = {
                "Content-Type": "text/javascript",
                "default-src": "https: 'unsafe-inline' 'unsafe-eval'; img-src https://* data: ; frame-src https://* about: javascript:",
                "X-WebKit-CSP-Report-Only": "default-src https: 'unsafe-inline' 'unsafe-eval'; img-src https://* data: ; frame-src https://* about: javascript:",
                "P3P": "policyref=\"/w3c/p3p.xml\", CP=\"NON CUR ADM DEV PSA PSD OUR IND UNI NAV INT STA\"",
                "Cache-Control": "no-cache, no-store, must-revalidate, private",
            }
            if request.path == "/platform/community/wormix_club":
                res = {
                    "uid": "15240126949415699923"
                }
                result = json.dumps(res, separators=(",", ":"))
                logger.debug(f"({self.server_type}) (port {WmxHttpServer.HTTP_PORT}) [{r_addr}] Response: {result}")
                return web.Response(text=result, headers=headers)
            elif request.path == "/platform/api":
                method = request.query.get("method", "")
                uids = request.query.get("uids", "")
                app_id = request.query.get("app_id", "")
                session_key = request.query.get("session_key", "")
                sig = request.query.get("sig", "")
                match(method):
                    case "users.getInfo":
                        user_profiles_social = []
                        new_user = {
                            "pic_50": "https://i.imgur.com/c0lNJJk.jpeg",
                            "video_count": 0,
                            "friends_count": 0,
                            "show_age": 1,
                            "nick": "@Kuroneko_yousenpai",
                            "is_friend": 0,
                            "is_online": 1,
                            "has_pic": 1,
                            "follower": 0,
                            "pic_190": "https://i.imgur.com/TC6HFfd.jpeg",
                            "referer_id": "",
                            "app_count": {
                                "web": 1,
                                "mob_web": 0
                            },
                            "following": 0,
                            "pic_32": "https://i.imgur.com/iio6wiL.jpeg",
                            "referer_type": "invalid",
                            "last_visit": 1730955169,
                            "uid": "466386210",
                            "app_installed": 1,
                            "status_text": "",
                            "pic_22": "https://i.imgur.com/wziCLBl.jpeg",
                            "has_my": 1,
                            "age": 15,
                            "last_name": "Hyakuya",
                            "is_verified": 0,
                            "pic_big": "https://i.imgur.com/TC6HFfd.jpeg", # 190
                            "vip": 0,
                            "birthday": "4.10.1999",
                            "link": "https://vk.com/Kuroneko_yousenpai",
                            "pic_128": "https://i.imgur.com/IoOgKMI.jpeg",
                            "sex": 0,
                            "pic": "https://i.imgur.com/wCLcrZC.jpeg",
                            "pic_small": "https://i.imgur.com/2i4NaSz.jpeg",
                            "pic_180": "https://i.imgur.com/0Glzv44.jpeg",
                            "first_name": "Mikaela",
                            "pic_40": "https://i.imgur.com/YMDORrL.jpeg"
                        }
                        user_profiles_social.append(new_user)
                        response_data = user_profiles_social
                        logger.info(f"({self.server_type}) (port {WmxHttpServer.HTTP_PORT}) [{r_addr}] Load MM users info")
                        result = json.dumps(response_data)
                        return web.Response(text=result, headers=headers)
                    case "friends.getAppUsers":
                        response_data = []
                        logger.info(f"({self.server_type}) (port {WmxHttpServer.HTTP_PORT}) [{r_addr}] Load MM friends list")
                        result = json.dumps(response_data)
                        return web.Response(text=result, headers=headers)
                    case _:
                        err_msg = {
                            "error": {
                                "error_msg": "Unknown method called",
                                "error_token": "NONE",
                                "extended": "null",
                                "error_code": 2
                            }
                        }
                        result = json.dumps(err_msg)
                        return web.Response(text=result, headers=headers)
            else:
                err_msg = {
                    "error": {
                        "error_msg": "Unknown api engine",
                        "error_token": "NONE",
                        "extended": "null",
                        "error_code": 2
                    }
                }
                result = json.dumps(err_msg)
                return web.Response(text=result, headers=headers)
        elif "fb.do" in request.path:  # OKRU api
            from email.utils import formatdate
            from multidict import CIMultiDict

            start_unixtime = formatdate(timeval=0, localtime=False, usegmt=True)
            headers = CIMultiDict({
                "server": "apache",
                "Content-Type": "application/json",
                "x-content-type-options": "nosniff",
                "invocation-error": "102",
                "pragma": "no-cache",
                "expires": start_unixtime,
                "content-language": "en-US",
            })
            headers.add("cache-control", "no-cache")
            headers.add("cache-control", "no-store")
            method = request.query.get("method", "")
            uids = request.query.get("uids", "")
            call_id = request.query.get("call_id", "")
            fields = request.query.get("fields", "")
            format = request.query.get("format", "")
            session_key = request.query.get("session_key", "")
            application_key = request.query.get("application_key", "")
            sig = request.query.get("sig", "")
            match (method):
                case "users.getInfo":
                    user_profiles_social = []
                    new_user = {
                        "uid": f"{uids}",
                        "locale": "ru"

                    }
                    user_profiles_social.append(new_user)
                    response_data = user_profiles_social
                    logger.info(f"({self.server_type}) (port {WmxHttpServer.HTTP_PORT}) [{r_addr}] Load OKRU user info")
                    result = json.dumps(response_data)
                    return web.Response(text=result, headers=headers)
                case "friends.getAppUsers":
                    response_data = []
                    logger.info(f"({self.server_type}) (port {WmxHttpServer.HTTP_PORT}) [{r_addr}] Load OKRU friends list")
                    result = json.dumps(response_data)
                    return web.Response(text=result, headers=headers)
                case _:
                    err_msg = {
                        "error": {
                            "error_msg": "Unknown method called",
                            "error_token": "NONE",
                            "extended": "null",
                            "error_code": 2
                        }
                    }
                    result = json.dumps(err_msg)
                    return web.Response(text=result, headers=headers)
        else:
            return web.Response(text="OK")

    async def handle_get_wrapper(self, request):
        try:
            return await self.handle_get(request)
        except Exception as err:
            return web.json_response({"error": str(err)}, status=500)

class WmxHttpServer():
    HTTP_IP_ADDRESS = "127.0.0.1"
    HTTP_PORT = 1337

    def __init__(self):
        self.server_type = "HTTP"

    async def run_http_server(self):
        wmx_http_server = WormixHTTPServer(self.server_type)
        app = web.Application(middlewares=[server_header_middleware, server_errors_middleware])
        app.router.add_get("/", wmx_http_server.handle_get_wrapper)
        app.router.add_get("/crossdomain.xml", wmx_http_server.handle_get_wrapper)
        # MM api
        app.router.add_get("/platform/community/wormix_club", wmx_http_server.handle_get_wrapper)
        app.router.add_get("/platform/api", wmx_http_server.handle_get_wrapper)
        # OKRU api
        app.router.add_get("/fb.do", wmx_http_server.handle_get_wrapper)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, WmxHttpServer.HTTP_IP_ADDRESS, WmxHttpServer.HTTP_PORT)
        await site.start()
        logger.info(f"Running HTTP-server: {self.HTTP_IP_ADDRESS}:{self.HTTP_PORT}")
        await asyncio.Event().wait()

def setup_logger():
    import sys

    LOGGER_LEVEL = "DEBUG"
    logger.remove()
    logger.add(sys.stdout,
               format="[<fg 255,185,255>{time:HH:mm:ss}</fg 255,185,255>] "
                      "[ <fg #FFA319>consollite</fg #FFA319> ] "
                      "[<level>{level}</level>] <fg #66FF66>{message}</fg #66FF66>",
               level=LOGGER_LEVEL,
               colorize=True)

    logger.level("TRACE", color="<fg #DCDCDC><b>")
    logger.level("DEBUG", color="<fg #66FF66><b>")
    logger.level("INFO", color="<fg #0064FF><b>")
    logger.level("SUCCESS", color="<fg #FF86FF><b>")
    logger.level("WARNING", color="<fg #FF9900><b>")
    logger.level("ERROR", color="<red><b>")
    logger.level("CRITICAL", color="<fg #FF1C1C><b>")

def main():
    setup_logger()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    wmx_http_server = WmxHttpServer()
    loop.run_until_complete(wmx_http_server.run_http_server())

if __name__ == "__main__":
    main()
