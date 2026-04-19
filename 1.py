# =================== 导入必需的标准库 ===================
# socket: 用于底层网络通信
# os: 用于文件系统操作
# logging: 用于记录日志
# RotatingFileHandler: 实现日志文件自动轮转，防止磁盘占满
# time: 用于时间戳和超时控制
# urllib.parse: 用于安全地解析和解码 URL
# ThreadPoolExecutor: 用于管理线程池，限制并发
# threading: 用于线程同步（锁）
# defaultdict, deque: 用于实现高效的滑动窗口限速
# re: 用于正则表达式，进行严格的文件名白名单校验
import socket
import os
import logging
from logging.handlers import RotatingFileHandler
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
import threading
from collections import defaultdict, deque
import re


# =================== 【核心安全配置】IP 白名单与黑名单 ===================
# 【白名单】只有在此集合中的 IP 地址才被允许访问服务器。
# 这是第一道也是最重要的防线。默认仅允许本地回环地址。
# 支持 IPv4 ('127.0.0.1') 和 IPv6 ('::1')。
ALLOWED_IPS = {
    '127.0.0.1',   # IPv4 本地回环地址
    '::1'          # IPv6 本地回环地址
    # 在此处添加您的可信客户端 IP，例如：
    # '192.168.1.100',
}

# 【黑名单】在此集合中的 IP 地址将被永久拒绝，即使它们也在白名单中。
# 黑名单的优先级高于白名单，用于手动封禁已知恶意 IP。
MANUAL_BLACKLIST = {
    # '203.0.113.10', # 示例：封禁一个恶意扫描器 IP
}


# =================== 日志系统初始化 ===================
def setup_logger():
    """
    初始化一个双通道日志系统，兼顾实时监控和长期审计。
    - 控制台：显示 INFO 及以上级别的日志，便于开发调试。
    - 文件：记录所有 DEBUG 级别日志，并自动轮转，防止日志文件过大。
    返回: 配置好的 logger 对象。
    """
    # 创建一个名为 "UltraSecureHTTPServer" 的日志记录器
    logger = logging.getLogger("UltraSecureHTTPServer")
    # 设置日志级别为 DEBUG，捕获所有级别的日志
    logger.setLevel(logging.DEBUG)

    # 防止在 IDE 中重复运行时产生重复的日志处理器
    if logger.handlers:
        logger.handlers.clear()

    # --- 配置控制台日志 ---
    console_handler = logging.StreamHandler()  # 创建控制台处理器
    console_handler.setLevel(logging.INFO)     # 只在控制台显示 INFO 及以上级别
    # 定义日志格式：时间 | 级别 | 消息
    console_formatter = logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # --- 配置文件日志 ---
    # 自动创建 logs 目录（如果不存在）
    if not os.path.exists("logs"):
        try:
            os.makedirs("logs", exist_ok=True)  # exist_ok=True 防止并发创建时出错
        except OSError as e:
            print(f"[严重错误] 无法创建日志目录 'logs': {e}")
            # 即使日志目录创建失败，也应继续运行，但会丢失文件日志
    # 创建一个轮转文件处理器，单个文件最大 10MB，保留 5 个备份
    file_handler = RotatingFileHandler(
        filename="logs/server.log",
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5,               # 保留5个历史文件
        encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG)  # 文件记录所有DEBUG级别日志
    file_formatter = logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    return logger


# =================== 全局配置与状态 ===================
# 初始化全局日志记录器
log = setup_logger()
PORT = 8080                 # 服务器监听端口
MAX_WORKERS = 2             # 最大工作线程数，极低以匹配1秒超时策略，防资源耗尽
CHUNK_SIZE = 32 * 1024      # 文件读取和发送的块大小 (32KB)
# 定义文件服务的根目录，使用 os.path.abspath 确保是绝对路径，防止相对路径问题
BASE_DIR = os.path.abspath('files')

# 【安全核心】文件白名单集合。启动时扫描 'files' 目录生成。
# 只有在此集合中的文件才允许被访问，这是防止任意文件读取的关键。
ALLOWED_FILES_SET = set()

# 【防御扫描】IP 请求频率限制。
# 使用 defaultdict(deque) 为每个 IP 维护一个时间戳队列，实现滑动窗口限速。
IP_REQUEST_LOG = defaultdict(deque)
REQUEST_LIMIT = 3           # 每个 IP 每分钟最多 3 次请求（非常严格，有效防扫描）
TIME_WINDOW = 60            # 时间窗口为 60 秒

# 【防御核心】运行时动态黑名单。初始值包含手动黑名单。
# 任何触发安全规则的 IP 都会被自动加入此集合。
BLACKLISTED_IPS = set(MANUAL_BLACKLIST)

# 【线程安全】保护所有共享数据结构（IP_REQUEST_LOG, BLACKLISTED_IPS）的锁。
# 所有对这些全局变量的读写操作都必须在 with ip_lock: 块内进行。
ip_lock = threading.Lock()


# =================== 【新增】安全辅助函数 ===================
def sanitize_for_log(s):
    """
    对日志中的用户输入进行脱敏处理，防止日志注入攻击或日志格式破坏。
    将换行符、回车符等替换为转义序列，并限制长度。
    参数: s - 任意对象
    返回: 脱敏后的字符串
    """
    try:
        if not isinstance(s, str):
            s = str(s)
        # 替换可能破坏日志格式的字符
        sanitized = s.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
        # 限制长度，防止超长日志
        return sanitized[:255]
    except Exception:
        # 极致容错：任何异常都返回一个安全的占位符
        return "<SANITIZE_ERROR>"


def is_filename_safe(filename):
    """
    【命令注入 & 路径遍历终极防御】校验文件名是否绝对安全。
    使用严格的正则白名单，只允许字母、数字、点、下划线和连字符。
    拒绝任何可能被操作系统或 shell 解释的特殊字符。
    参数: filename - 文件名（不包含路径）
    返回: True 如果安全，False 如果危险
    """
    if not isinstance(filename, str):
        return False
    # 正则解释: ^ 表示开头, $ 表示结尾, [a-zA-Z0-9._-] 是允许的字符集, + 表示一个或多个
    # 同时检查长度，防止超长文件名 DoS
    return bool(re.match(r'^[a-zA-Z0-9._\-]+$', filename)) and (1 <= len(filename) <= 255)


# =================== 构建文件白名单 ===================
def build_whitelist():
    """
    在服务器启动时，安全地扫描 'files' 目录，构建一个只读的文件白名单。
    此过程会过滤掉所有隐藏文件、敏感扩展名文件和文件名不安全的文件。
    这是防止服务器泄露敏感信息（如 .env, .git）的第一步。
    """
    global ALLOWED_FILES_SET
    allowed = set()
    # 定义一组常见的敏感文件扩展名，这些文件绝不应该被公开
    sensitive_exts = {'.env', '.git', '.gitignore', '.htaccess', '.log', '.bak', '.tmp', '.py', '.pyc', '.yml', '.yaml'}

    # 检查基础目录是否存在且是一个目录
    if os.path.exists(BASE_DIR) and os.path.isdir(BASE_DIR):
        try:
            # 使用 os.walk 安全地遍历目录树
            for root, _, files in os.walk(BASE_DIR):
                for file in files:
                    # 规则1: 跳过所有以 '.' 开头的隐藏文件
                    if file.startswith('.'):
                        continue
                    # 规则2: 跳过所有敏感扩展名的文件（不区分大小写）
                    if any(file.lower().endswith(ext) for ext in sensitive_exts):
                        log.warning(f"[白名单跳过] 敏感文件被忽略: {sanitize_for_log(file)}")
                        continue
                    # 【新增规则3】: 跳过文件名不安全的文件（命令注入/路径遍历防御）
                    if not is_filename_safe(file):
                        log.warning(f"[白名单跳过] 文件名包含危险字符，被忽略: {sanitize_for_log(file)}")
                        continue

                    # 构建完整的绝对路径，并加入白名单集合
                    full_path = os.path.abspath(os.path.join(root, file))
                    allowed.add(full_path)
            log.info(f"[白名单] 成功加载 {len(allowed)} 个可安全访问的文件。")
        except Exception as e:
            log.critical(f"[白名单构建失败] 遍历目录时发生异常: {e}", exc_info=True)
    else:
        log.error(f"[致命错误] 基础目录 '{BASE_DIR}' 不存在或不是一个目录！请创建 'files' 文件夹。")

    # 原子性地更新全局白名单
    ALLOWED_FILES_SET = allowed


# =================== IP 访问控制逻辑 ===================
def is_ip_allowed(client_ip):
    """
    【核心访问控制】判断一个客户端 IP 是否被允许访问。
    采用“黑名单优先”原则：
        1. 如果 IP 在黑名单中，立即拒绝。
        2. 否则，如果 IP 在白名单中，允许访问。
        3. 否则，拒绝访问。
    所有操作都在锁内进行，保证线程安全。
    返回: (bool, str) - (是否允许, 拒绝原因)
    """
    try:
        with ip_lock:
            if client_ip in BLACKLISTED_IPS:
                return False, "blacklisted"
            if client_ip in ALLOWED_IPS:
                return True, "whitelisted"
            return False, "not_in_whitelist"
    except Exception as e:
        # 极致容错：即使锁操作失败，也应拒绝访问
        log.debug(f"[IP校验异常] 锁操作失败: {e}")
        return False, "error"


def add_to_blacklist(ip, reason="manual"):
    """
    安全地将一个 IP 地址加入黑名单。
    此函数用于自动封禁触发安全规则的 IP（如高频请求、路径遍历尝试）。
    """
    try:
        with ip_lock:
            if ip not in BLACKLISTED_IPS:
                BLACKLISTED_IPS.add(ip)
                log.warning(f"[自动封禁] IP {ip} 因 '{reason}' 被加入黑名单。")
    except Exception as e:
        log.debug(f"[加入黑名单失败] 操作异常: {e}")


def is_rate_limited(client_ip):
    """
    【防扫描核心】实现基于滑动窗口的请求频率限制。
    如果一个 IP 在 TIME_WINDOW (60秒) 内的请求次数超过 REQUEST_LIMIT (3次)，
    该 IP 将被自动加入黑名单。
    """
    now = time.time()
    try:
        with ip_lock:
            # 如果 IP 已经在黑名单中，直接返回 True
            if client_ip in BLACKLISTED_IPS:
                return True

            # 获取或创建该 IP 的请求时间戳队列
            queue = IP_REQUEST_LOG[client_ip]
            # 清理队列中过期的时间戳（早于 now - TIME_WINDOW 的）
            while queue and queue[0] < now - TIME_WINDOW:
                queue.popleft()

            # 检查当前队列长度是否超过限制
            if len(queue) >= REQUEST_LIMIT:
                # 超限！自动封禁该 IP
                add_to_blacklist(client_ip, reason="auto_rate_limit_exceeded")
                return True

            # 记录本次请求的时间戳
            queue.append(now)
            return False
    except Exception as e:
        # 容错：限速功能异常不应影响主流程，选择不拦截
        log.debug(f"[速率限制异常] {e}")
        return False


# =================== 【终极防御】安全路径解析与多重校验 ===================
def safe_join_and_validate(base, url_path):
    """
    【最高安全级别】对来自 HTTP 请求的 URL 路径进行多层、纵深的安全校验。
    目标：彻底杜绝路径遍历、命令注入、空字节攻击等所有已知漏洞。
    参数:
        base: 文件服务的根目录 (BASE_DIR)
        url_path: 原始的 URL 路径 (如 "/../../../etc/passwd")
    返回: 合法的本地绝对文件路径，或 None (表示非法请求)
    """
    # --- 校验1: 处理根路径 "/" 请求 ---
    if url_path == '/' or not url_path.strip('/'):
        # 尝试返回 index.html
        potential_index = os.path.join(base, 'index.html')
        abs_index = os.path.abspath(potential_index)
        # 只有当 index.html 本身在白名单中时才返回
        return abs_index if abs_index in ALLOWED_FILES_SET else None

    # --- 校验2: URL 解码 (UTF-8 严格模式) ---
    # 使用 errors='strict' 确保任何非法字节序列都会导致解码失败
    try:
        decoded = urllib.parse.unquote(url_path, encoding='utf-8', errors='strict')
    except UnicodeDecodeError:
        log.warning(f"[安全拦截] URL 包含无法解码的非法字节序列: {sanitize_for_log(url_path)}")
        return None

    # --- 校验3: 【命令注入防御】检查危险字符 ---
    # 定义一个包含常见命令注入和路径遍历字符的集合
    dangerous_chars = {'|', '&', ';', '$', '`', '(', ')', '<', '>', '\'', '"', '\\', '\x00', '\n', '\r'}
    if any(char in decoded for char in dangerous_chars):
        log.warning(f"[安全拦截] 请求路径包含命令注入/路径遍历危险字符: {sanitize_for_log(decoded)}")
        return None

    # --- 校验4: 路径长度限制 ---
    # 防止超长路径导致的内存耗尽或解析异常
    if len(decoded) > 256:
        log.warning(f"[安全拦截] 请求路径过长 ({len(decoded)} 字符)，疑似 DoS 攻击。")
        return None

    # --- 校验5: 路径规范化与 ".." 检查 ---
    # 使用 os.path.normpath 规范化路径，并移除开头的 '/' 或 '\'
    normalized = os.path.normpath(decoded).lstrip('/').lstrip('\\')
    # 显式检查路径分隔后的任何部分是否包含 ".."
    if '..' in normalized.split(os.sep):
        log.warning(f"[安全拦截] 路径遍历攻击尝试 ('..'): {sanitize_for_log(url_path)}")
        return None

    # --- 校验6: 路径深度限制 ---
    # 防止超深嵌套路径（如 a/b/c/d/.../z）导致的性能问题
    depth = len(normalized.split(os.sep))
    if depth > 5:
        log.warning(f"[安全拦截] 路径嵌套过深 ({depth} 层)，疑似扫描行为。")
        return None

    # --- 校验7: 【终极防御】最终文件名安全校验 ---
    # 即使路径看起来合法，也要确保最终的文件名是安全的
    final_filename = os.path.basename(normalized)
    if not is_filename_safe(final_filename):
        log.warning(f"[安全拦截] 最终文件名不安全: {sanitize_for_log(final_filename)}")
        return None

    # --- 校验8: 拼接完整路径 ---
    full_path = os.path.join(base, normalized)

    # --- 校验9: 目录穿越防护 (使用 os.path.commonpath) ---
    # 这是最可靠的防护方式，确保解析后的路径仍在 BASE_DIR 内
    try:
        base_abs = os.path.abspath(base)
        full_abs = os.path.abspath(full_path)
        # commonpath 返回两个路径的公共前缀，如果不是 base_abs，则说明越界了
        if os.path.commonpath([base_abs, full_abs]) != base_abs:
            log.warning(f"[安全拦截] 目录穿越攻击！请求路径: {sanitize_for_log(url_path)}")
            return None
    except ValueError:
        # 处理跨盘符等特殊情况（在 Windows 上可能发生）
        log.warning(f"[安全拦截] 跨盘符路径攻击！请求: {sanitize_for_log(url_path)}")
        return None

    # --- 校验10: 白名单最终验证 ---
    # 这是最后一道防线，确保文件确实在启动时被扫描并加入白名单
    if full_abs not in ALLOWED_FILES_SET:
        log.warning(f"[安全拦截] 请求的文件不在白名单中: {sanitize_for_log(full_abs)}")
        return None

    # 所有校验通过，返回安全的绝对路径
    return full_abs


# =================== MIME 类型映射 ===================
def get_content_type(filepath):
    """
    根据文件扩展名返回正确的 Content-Type。
    防止浏览器错误解析文件类型（如将 txt 当作 html 执行）。
    同时包含 Content-Type 注入防御。
    """
    try:
        ext = os.path.splitext(filepath)[1].lower()
        mime_map = {
            '.html': 'text/html; charset=utf-8',
            '.txt': 'text/plain; charset=utf-8',
            '.exe': 'application/octet-stream',
            '.zip': 'application/zip',
            '.pdf': 'application/pdf',
        }
        content_type = mime_map.get(ext, 'application/octet-stream')
        # 防御性检查：确保 Content-Type 中不包含 CRLF，防止响应拆分攻击
        if '\r' in content_type or '\n' in content_type:
            return 'application/octet-stream'
        return content_type
    except Exception:
        # 容错：任何异常都返回最安全的通用类型
        return 'application/octet-stream'


# =================== 伪造 Apache 错误页面 ===================
def generate_fake_apache_error(code, title):
    """
    生成一个模仿 Apache Web 服务器的错误页面。
    目的：隐藏后端真实技术栈（Python, 自研服务器），增加攻击者探测难度。
    """
    body = f"""<!DOCTYPE html>
<html><head><title>{code} {title}</title>
<style>body{{font-family:monospace;background:#f6f6f6;}}
.container{{width:600px;margin:5em auto;padding:2em;background:white;border-radius:0.5em;}}
h1{{color:#a94442;}}</style></head>
<body><div class="container">
<h1>{code} {title}</h1>
<p>The requested URL was not found on this server.</p>
<hr><address>Apache/2.4.41 (Ubuntu) Server at localhost Port 80</address>
</div></body></html>"""
    return body.encode('utf-8')


def send_fake_error(conn, code, title):
    """
    向客户端发送一个伪造的 Apache 风格错误响应。
    所有非法请求（403, 404, 400等）都统一由此函数处理，对外表现一致。
    """
    try:
        body = generate_fake_apache_error(code, title)
        response = (
                       f"HTTP/1.1 {code} {title}\r\n"
                       "Content-Type: text/html; charset=utf-8\r\n"
                       f"Content-Length: {len(body)}\r\n"
                       "Connection: close\r\n"
                       "Server: Apache/2.4.41 (Ubuntu)\r\n"
                       "\r\n"
                   ).encode('utf-8') + body
        # 发送错误页也受 1 秒超时约束
        conn.settimeout(1.0)
        conn.sendall(response)
    except Exception as e:
        log.debug(f"[发送错误页失败] {e}")


# =================== 客户端请求处理主逻辑 ===================
def handle_client(conn, addr):
    """
    处理单个客户端连接的主函数。
    采用“尽早失败”原则，在请求处理的最早阶段就进行安全检查。
    """
    client_ip = addr[0]
    start_time = time.time()
    requested_path = "/"

    # --- 【第一道防线】IP 白名单/黑名单校验 (在 recv 之前!) ---
    # 这能最大程度节省服务器资源，恶意 IP 甚至无法发送数据
    allowed, reason = is_ip_allowed(client_ip)
    if not allowed:
        _log_and_reject_ip(client_ip, reason)
        _close_connection_safely(conn)
        return

    # --- 【第二道防线】设置极短的 Socket 超时 (1秒) ---
    # 这是防御 Slowloris 等慢速 HTTP 攻击的关键
    conn.settimeout(1.0)

    try:
        # --- 【第三道防线】请求频率限制 ---
        if is_rate_limited(client_ip):
            send_fake_error(conn, 403, "Forbidden")
            return

        # --- 接收客户端请求 ---
        # 限制接收缓冲区为 1024 字节，足够解析请求行，防止大请求耗尽内存
        data = conn.recv(1024)
        if not data:
            return

        # --- 【第四道防线】严格解析 HTTP 请求行 ---
        # 只取第一行 (b'\r\n' 分割)，并限制其长度
        request_line = data.split(b'\r\n', 1)[0]
        if len(request_line) > 512:  # 防止超长请求行
            send_fake_error(conn, 400, "Bad Request")
            return

        # 尝试用 ASCII 解码请求行（HTTP 方法和路径应为 ASCII）
        parts = request_line.decode('ascii', errors='ignore').split()
        if len(parts) < 2 or len(parts) > 3:  # 标准格式: METHOD PATH [HTTP/VERSION]
            send_fake_error(conn, 400, "Bad Request")
            return

        method, raw_url_path = parts[0], parts[1]
        # --- 【第五道防线】只允许 GET 方法 ---
        if method != "GET":
            send_fake_error(conn, 405, "Method Not Allowed")
            return

        # --- 【第六道防线】终极路径安全校验 ---
        local_path = safe_join_and_validate(BASE_DIR, raw_url_path)
        if local_path is None:
            # 安全最佳实践：统一返回 404，不向攻击者透露 403 (Forbidden) 信息
            send_fake_error(conn, 404, "Not Found")
            return

        # --- 准备发送文件 ---
        # 【极致容错】文件大小获取单独 try-except
        try:
            file_size = os.path.getsize(local_path)
        except (OSError, FileNotFoundError):
            log.error(f"[文件系统错误] 无法获取文件大小 (可能已被删除): {sanitize_for_log(local_path)}")
            send_fake_error(conn, 404, "Not Found")
            return

        content_type = get_content_type(local_path)

        # 构建并发送 HTTP 响应头
        headers = (
            "HTTP/1.1 200 OK\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {file_size}\r\n"
            "Connection: close\r\n"
            "Server: Apache/2.4.41 (Ubuntu)\r\n"
            "\r\n"
        ).encode('utf-8')
        conn.sendall(headers)

        # 【极致容错】文件读取与发送
        try:
            with open(local_path, 'rb') as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    conn.sendall(chunk)
            log.info(f"[成功] 已安全返回文件: {sanitize_for_log(local_path)} ({file_size} 字节) 到 {client_ip}")
        except (OSError, IOError) as e:
            log.error(f"[文件传输中断] {sanitize_for_log(local_path)}: {e}")

    # --- 异常处理 ---
    except socket.timeout:
        log.warning(f"[连接超时] 客户端 {client_ip} 未在 1 秒内完成交互。")
    except ConnectionResetError:
        log.debug(f"[连接重置] 客户端 {client_ip} 主动断开连接。")
    except Exception as e:
        # 记录完整异常堆栈，便于事后分析
        log.exception(f"[未知异常] 处理 {client_ip} 的请求时发生未预期错误。")
        try:
            send_fake_error(conn, 404, "Not Found")
        except:
            pass  # 发送错误页失败也无妨
    finally:
        # 无论成功与否，都确保连接被安全关闭
        _close_connection_safely(conn)
        duration = (time.time() - start_time) * 1000
        log.debug(f"[请求完成] {client_ip} -> {requested_path} | 耗时: {duration:.2f}ms")


# =================== 内部辅助函数 ===================
def _log_and_reject_ip(client_ip, reason):
    """统一处理 IP 拒绝的日志记录"""
    if reason == "blacklisted":
        log.warning(f"[访问拒绝] 黑名单 IP 尝试连接: {client_ip}")
    elif reason == "not_in_whitelist":
        log.warning(f"[访问拒绝] 非白名单 IP 尝试连接: {client_ip}")
    else:
        log.warning(f"[访问拒绝] IP 校验失败: {client_ip}")


def _close_connection_safely(conn):
    """以极致容错的方式关闭 socket 连接"""
    try:
        conn.shutdown(socket.SHUT_RDWR)
    except (OSError, socket.error):
        pass  # shutdown 失败是正常的，比如连接已断开
    try:
        conn.close()
    except (OSError, socket.error):
        pass  # close 失败也无妨


# =================== 主程序入口 ===================
def main():
    """服务器主启动函数"""
    # 启动时构建文件白名单
    build_whitelist()
    # 记录关键配置到日志
    log.info(f"[配置] 允许访问的 IP 白名单: {sorted(ALLOWED_IPS)}")
    log.info(f"[配置] 手动设置的 IP 黑名单: {sorted(MANUAL_BLACKLIST)}")
    log.info(f"[配置] 文件服务根目录: {BASE_DIR}")
    log.info(f"[配置] 最大并发线程数: {MAX_WORKERS} | Socket 超时: 1.0 秒")
    log.info(f"[配置] 请求频率限制: {REQUEST_LIMIT} 次 / {TIME_WINDOW} 秒 / IP")

    # 创建并配置服务器 socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 设置 SO_REUSEADDR，允许快速重启服务器
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # 创建一个固定大小的线程池
    executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

    try:
        # 绑定端口并开始监听
        server_socket.bind(('', PORT))
        server_socket.listen(10)  # 连接队列长度
        log.info("=" * 60)
        log.info(f"[服务启动] 高安全文件服务器已在 http://127.0.0.1:{PORT}/ 上运行！")
        log.info("[重要提示] 仅白名单内的 IP 可以访问，其他所有请求均被拒绝。")
        log.info("=" * 60)

        # 主事件循环
        while True:
            try:
                # 接受新连接
                conn, addr = server_socket.accept()
                # 提交任务到线程池
                executor.submit(handle_client, conn, addr)
            except KeyboardInterrupt:
                log.info("[用户中断] 收到 SIGINT 信号，正在关闭服务器...")
                break
            except Exception as e:
                log.critical(f"[主循环异常] 接受连接时发生错误: {e}", exc_info=True)

    except Exception as e:
        log.critical(f"[启动失败] 无法绑定到端口 {PORT}: {e}", exc_info=True)
    finally:
        # 优雅关闭
        executor.shutdown(wait=False)
        server_socket.close()
        log.info("[服务停止] 服务器已完全退出。")


# =================== 程序入口点 ===================
if __name__ == '__main__':
    main()