import logging
from flask import Flask, render_template, request, jsonify
import requests
import time
import dns.resolver
import ssl
import nmap
import subprocess
import platform
from cachetools import TTLCache
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import socket
import certifi
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from tenacity import retry, stop_after_attempt, wait_fixed
import validators


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

cache = TTLCache(maxsize=100, ttl=300)
executor = ThreadPoolExecutor(max_workers=10)


def get_ip_from_domain(domain):
    try:
        answers = dns.resolver.resolve(domain, "A")
        return answers[0].to_text(), None
    except Exception as e:
        logger.error(f"Error resolving domain {domain}: {e}")
        return None, str(e)


def fetch_page_load_time(url):
    start_time = time.time()
    try:
        if not validators.url(url):
            raise ValueError("Неверный формат URL")

        requests.get(url, timeout=10)
        load_time = time.time() - start_time
        logger.info(f"Page load time for {url}: {load_time} seconds")
        return load_time, None
    except ValueError as e:
        logger.error(f"Validation error for URL {url}: {e}")
        return None, f"Ошибка валидации URL: {e}"
    except requests.exceptions.RequestException as e:
        logger.error(f"Error loading page {url}: {e}")
        return None, f"Ошибка загрузки страницы: {e}"


def fetch_dns_info(clean_url):
    try:
        if not validators.domain(clean_url):
            raise ValueError("Неверный формат домена")

        domain = clean_url.split("//")[-1].split("/")[0]
        ip_addresses = socket.gethostbyname_ex(domain)[2]
        logger.info(f"DNS info for {domain}: {ip_addresses}")
        return ip_addresses, None
    except ValueError as e:
        logger.error(f"Validation error for domain {clean_url}: {e}")
        return None, f"Ошибка валидации домена: {e}"
    except Exception as e:
        logger.error(f"Error fetching DNS info for {clean_url}: {e}")
        return None, f"Ошибка при получении IP-адресов: {e}"


def fetch_ssl_info(clean_url):
    try:
        if not validators.domain(clean_url):
            raise ValueError("Неверный формат домена")

        domain = clean_url.split("//")[-1].split("/")[0]
        context = ssl.create_default_context(cafile=certifi.where())
        with context.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, 443))
            cert = s.getpeercert(True)
            cert_obj = x509.load_der_x509_certificate(cert, default_backend())

        not_before = cert_obj.not_valid_before_utc
        not_after = cert_obj.not_valid_after_utc
        serial_number = cert_obj.serial_number
        now = datetime.now(timezone.utc)

        validity_status = "действителен"
        if now < not_before:
            validity_status = "не действителен, ещё не начался"
        elif now > not_after:
            validity_status = "не действителен, срок истёк"

        ssl_info = {
            "validity_status": validity_status,
            "not_before": not_before.strftime("%d-%m-%Y %H:%M:%S"),
            "not_after": not_after.strftime("%d-%m-%Y %H:%M:%S"),
            "serial_number": format(serial_number, "X"),
        }
        logger.info(f"SSL info for {domain}: {ssl_info}")
        return ssl_info, None
    except ValueError as e:
        logger.error(f"Validation error for domain {clean_url}: {e}")
        return None, f"Ошибка валидации домена: {e}"
    except ssl.SSLError as e:
        logger.error(f"SSL error for {clean_url}: {e}")
        return None, f"Ошибка SSL: {e}"
    except Exception as e:
        logger.error(f"Error fetching SSL info for {clean_url}: {e}")
        return None, f"Ошибка проверки SSL: {e}"


@retry(stop=stop_after_attempt(3), wait=wait_fixed(5))
def ping_ip(ip):
    try:
        if platform.system().lower() == "windows":
            output = subprocess.check_output(
                ["ping", "-n", "4", ip],
                universal_newlines=True,
                encoding="cp866",
                timeout=20,
            )
        else:
            output = subprocess.check_output(
                ["ping", "-c", "4", ip],
                universal_newlines=True,
                timeout=20,
            )
        cleaned_output = output.replace("\n", "<br>").replace("\r", "")
        return {"status": "доступен", "output": cleaned_output}
    except subprocess.CalledProcessError as e:
        logger.error(f"Ping command failed for {ip}: {e.output}")
        raise
    except Exception as e:
        logger.error(f"Unknown error during ping for {ip}: {str(e)}")
        raise


@app.route("/", methods=["GET", "POST"])
def index():
    error_message = None
    if request.method == "POST":
        url = request.form.get("url")
        if not url:
            error_message = "URL не указан"
            return render_template("index.html", error_message=error_message)
        if not validators.url(url):
            error_message = "Неверный формат URL"
            return render_template("index.html", error_message=error_message)

        clean_url = url.replace("http://", "").replace("https://", "").split("/")[0]
        cache_key = f"{clean_url}_data"

        if cache_key in cache:
            load_time, dns_info, ssl_info, scan_result = cache[cache_key]
        else:
            future_load_time = executor.submit(fetch_page_load_time, url)
            future_dns_info = executor.submit(fetch_dns_info, clean_url)
            future_ssl_info = executor.submit(fetch_ssl_info, clean_url)
            future_scan_result = executor.submit(fetch_scan_result, clean_url)

            load_time, error = future_load_time.result()
            dns_info, error = future_dns_info.result()
            ssl_info, error = future_ssl_info.result()
            scan_result, error = future_scan_result.result()

            if error:
                logger.error(f"Error in index route: {error}")
                error_message = f"Ошибка: {error}"
                return render_template("index.html", error_message=error_message)

            cache[cache_key] = (load_time, dns_info, ssl_info, scan_result)

        return render_template(
            "result.html",
            load_time=load_time,
            dns_info=dns_info,
            ssl_info=ssl_info,
            scan_result=scan_result,
            url=url,
        )

    return render_template("index.html", error_message=error_message)


@app.route("/ping", methods=["POST"])
def ping():
    host = request.json.get("host")
    if not host:
        return jsonify({"result": "Нет указанного хоста для ping."})

    ip_addresses, error = fetch_dns_info(host)
    if error:
        return jsonify({"result": error})

    ping_results = {}
    for ip in ip_addresses:
        try:
            ping_results[ip] = ping_ip(ip)
            logger.info(f"Ping result for {ip}: {ping_results[ip]}")
        except subprocess.CalledProcessError as e:
            ping_results[ip] = {
                "status": "недоступен",
                "output": f"Ошибка при выполнении ping: {e.output}",
            }
            logger.error(f"Ping error for {ip}: {e.output}")
        except Exception as e:
            ping_results[ip] = {
                "status": "ошибка",
                "output": f"Неизвестная ошибка: {str(e)}",
            }
            logger.error(f"Unknown ping error for {ip}: {str(e)}")

    return jsonify({"results": ping_results, "status": "Ping завершен"})


def get_port_name(port):
    try:
        # Attempt to get the service name for the given port
        return socket.getservbyport(port)
    except OSError:
        # If no standard service name exists for the port, return "unknown"
        return "unknown"


@retry(stop=stop_after_attempt(3), wait=wait_fixed(5))
def fetch_scan_result(ip, ports="1-1024", max_threads=100):
    scan_result = {ip: []}

    def scan_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # Reduced timeout to speed up scanning
            result = sock.connect_ex((ip, port))
            sock.close()
            # Get the port name
            port_name = get_port_name(port)
            # Only return the port result if the name is not "unknown"
            if port_name != "unknown":
                return {
                    "port": port,
                    "name": port_name,
                    "state": "open" if result == 0 else "closed",
                }
            else:
                # Skip adding this port to the result if the name is "unknown"
                return None
        except Exception as e:
            logger.error(f"Error scanning port {port} on {ip}: {e}")
            # Only include the port in the result if its name is not "unknown"
            port_name = get_port_name(port)
            if port_name != "unknown":
                return {"port": port, "name": port_name, "state": "error"}
            else:
                return None

    try:
        # Split ports and create a list of ports to scan
        ports_to_scan = ports.split(",")
        all_ports = []

        for port_range in ports_to_scan:
            # Check if the element is a range of ports (e.g., "1-1024")
            if "-" in port_range:
                start_port, end_port = map(int, port_range.split("-"))
                all_ports.extend(range(start_port, end_port + 1))
            else:
                all_ports.append(int(port_range))

        # Use ThreadPoolExecutor to scan ports concurrently
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_port = {
                executor.submit(scan_port, port): port for port in all_ports
            }
            for future in as_completed(future_to_port):
                try:
                    port_result = future.result()
                    # Only append the result if it's not None
                    if port_result is not None:
                        scan_result[ip].append(port_result)
                except Exception as e:
                    logger.error(
                        f"Error retrieving scan result for port {future_to_port[future]}: {e}"
                    )
                    # Handle errors but skip ports with "unknown" names
                    port_name = get_port_name(future_to_port[future])
                    if port_name != "unknown":
                        scan_result[ip].append(
                            {
                                "port": future_to_port[future],
                                "name": port_name,
                                "state": "error",
                            }
                        )

        logger.info(f"Scan result for {ip}: {scan_result}")
        return scan_result, None

    except Exception as e:
        logger.error(f"Error during scanning for {ip}: {e}")
        return None, f"Ошибка сканирования: {e}"


@app.route("/scan", methods=["POST"])
def scan():
    host = request.json.get("host")
    if not host:
        return jsonify({"result": "Нет указанного хоста для сканирования."})

    ports = request.json.get("ports", "1-1024")
    ip_addresses, error = fetch_dns_info(host)
    if error:
        return jsonify({"result": f"Ошибка при получении IP-адреса: {error}"})

    scan_results = {}
    for ip in ip_addresses:
        try:
            scan_result, error = fetch_scan_result(ip)
            if error:
                scan_results[ip] = {"error": error}
            else:
                scan_results[ip] = scan_result[ip]
            logger.info(f"Scan result for {ip}: {scan_result}")
        except Exception as e:
            scan_results[ip] = {
                "error": f"Ошибка при выполнении Nmap сканирования: {e}"
            }
            logger.error(f"Error performing Nmap scan for {ip}: {e}")

    return jsonify({"result": scan_results, "status": "Сканирование завершено"})


if __name__ == "__main__":
    app.run(debug=True)
