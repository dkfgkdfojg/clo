# analyzers/photo.py
import os
import time
from urllib.parse import quote
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

from core.http import get_session, safe_get
from core.utils import dual_print, print_section, print_field, print_summary, logger
from core.browser import build_chrome_driver  # <--- новое


def get_exif_data(image_path):
    """Извлекает метаданные из изображения (EXIF, GPS, IPTC)."""
    try:
        img = Image.open(image_path)
        exifdata = img.getexif()
        if not exifdata:
            return {"error": "Нет EXIF-данных"}

        metadata = {}
        for tag_id, value in exifdata.items():
            tag = TAGS.get(tag_id, tag_id)
            if tag == "GPSInfo":
                # Обработка GPS-координат
                gps_data = {}
                for gps_tag in value:
                    sub_tag = GPSTAGS.get(gps_tag, gps_tag)
                    gps_data[sub_tag] = value[gps_tag]
                if "GPSLatitude" in gps_data and "GPSLongitude" in gps_data:
                    lat = gps_data["GPSLatitude"]
                    lon = gps_data["GPSLongitude"]
                    lat_ref = gps_data.get("GPSLatitudeRef", "N")
                    lon_ref = gps_data.get("GPSLongitudeRef", "E")
                    # Преобразование в градусы
                    lat_deg = float(lat[0]) + float(lat[1]) / 60 + float(lat[2]) / 3600
                    lon_deg = float(lon[0]) + float(lon[1]) / 60 + float(lon[2]) / 3600
                    if lat_ref == "S":
                        lat_deg = -lat_deg
                    if lon_ref == "W":
                        lon_deg = -lon_deg
                    metadata["GPS"] = f"{lat_deg:.6f}, {lon_deg:.6f}"
            else:
                metadata[tag] = str(value)
        return metadata
    except Exception as e:
        logger.debug(f"EXIF extraction error: {e}")
        return {"error": str(e)}


def analyze_photo(image_path):
    """
    Анализ фотографии:
      - Извлечение метаданных (EXIF, GPS)
      - FaceCheck (Selenium)
      - GeoSpy (POST)
      - Picarta.ai
      - Labs.TIB.EU (GeoEstimation)
      - Search4Faces
    """
    dual_print(f"\n{'═' * 58}")
    dual_print(f"  [+] АНАЛИЗ ФОТО: {os.path.basename(image_path)}")
    dual_print(f"{'═' * 58}")

    if not os.path.isfile(image_path):
        dual_print("  [!] Файл не найден.")
        return

    session = get_session()
    results = {}

    # ---------- 0. МЕТАДАННЫЕ ----------
    print_section("Метаданные изображения")
    meta = get_exif_data(image_path)
    if "error" in meta:
        dual_print(f"  [–] {meta['error']}")
    else:
        # Выводим только интересные поля
        important = [
            "Make",
            "Model",
            "DateTime",
            "DateTimeOriginal",
            "ExposureTime",
            "FNumber",
            "ISO",
            "FocalLength",
            "GPS",
            "Software",
        ]
        for key in important:
            if key in meta:
                print_field(key, meta[key])
                results[key] = meta[key]
        # Если есть другие поля, покажем их кратко
        other = {k: v for k, v in meta.items() if k not in important}
        if other:
            dual_print("  Дополнительные метаданные:")
            for k, v in list(other.items())[:10]:
                dual_print(f"    • {k}: {v[:100] if len(str(v)) > 100 else v}")

    # ---------- 1. FACECHECK.ID (Selenium) ----------
    def facecheck():
        driver = None
        try:
            print_section("FaceCheck")
            driver = build_chrome_driver()
            driver.get("https://facecheck.id/")
            upload = WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "input[type='file']"))
            )
            upload.send_keys(os.path.abspath(image_path))
            WebDriverWait(driver, 30).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, ".result-item"))
            )
            for el in driver.find_elements(By.CSS_SELECTOR, ".result-item a"):
                href = el.get_attribute("href")
                if href:
                    print_field("FaceCheck", href)
                    results["facecheck"] = href
        except Exception as e:
            logger.debug(f"FaceCheck error: {e}")
            dual_print(f"  [!] FaceCheck: {e}")
        finally:
            if driver:
                try:
                    driver.quit()
                except Exception:
                    pass

    # ---------- 2. GEOSPY ----------
    def geospy():
        try:
            print_section("GeoSpy")
            with open(image_path, "rb") as f:
                files = {"image": (os.path.basename(image_path), f, "image/jpeg")}
                r = session.post(
                    "https://geospy.web.app/upload", files=files, timeout=20
                )
            if r.status_code == 200:
                data = r.json()
                if data.get("coordinates"):
                    print_field("GeoSpy (координаты)", data["coordinates"])
                    results["geospy"] = data["coordinates"]
                if data.get("country"):
                    print_field("GeoSpy (страна)", data["country"])
        except Exception as e:
            logger.debug(f"GeoSpy error: {e}")
            dual_print(f"  [!] GeoSpy: {e}")

    # ---------- 3. PICARTA.AI ----------
    def picarta():
        try:
            print_section("Picarta.ai")
            with open(image_path, "rb") as f:
                files = {"file": (os.path.basename(image_path), f, "image/jpeg")}
                r = session.post("https://picarta.ai/upload", files=files, timeout=20)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                loc = soup.select_one(".location")
                if loc:
                    print_field("Picarta", loc.text.strip())
                    results["picarta"] = loc.text.strip()
        except Exception as e:
            logger.debug(f"Picarta error: {e}")
            dual_print(f"  [!] Picarta: {e}")

    # ---------- 4. LABS.TIB.EU (GeoEstimation) ----------
    def geoestimation():
        try:
            print_section("Labs.TIB.EU (GeoEstimation)")
            with open(image_path, "rb") as f:
                files = {"image": (os.path.basename(image_path), f, "image/jpeg")}
                r = session.post(
                    "https://labs.tib.eu/geoestimation/upload", files=files, timeout=20
                )
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                for el in soup.select(".result-item, .prediction"):
                    txt = el.get_text(strip=True)
                    if txt and "lat" not in txt.lower():
                        dual_print(f"  {txt}")
                        results["geoestimation"] = txt
        except Exception as e:
            logger.debug(f"GeoEstimation error: {e}")
            dual_print(f"  [!] GeoEstimation: {e}")

    # ---------- 5. SEARCH4FACES ----------
    def search4faces():
        try:
            print_section("Search4Faces")
            with open(image_path, "rb") as f:
                files = {"photo": (os.path.basename(image_path), f, "image/jpeg")}
                r = session.post(
                    "http://search4faces.com/upload", files=files, timeout=20
                )
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                for link in soup.select('a[href*="result"]'):
                    href = link.get("href")
                    if href and "http" in href:
                        print_field("Search4Faces", href)
                        results["search4faces"] = href
        except Exception as e:
            logger.debug(f"Search4Faces error: {e}")
            dual_print(f"  [!] Search4Faces: {e}")

    # ---------- ПАРАЛЛЕЛЬНЫЙ ЗАПУСК ----------
    print_section("Параллельный запуск анализаторов фото...")
    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = [
            ex.submit(facecheck),
            ex.submit(geospy),
            ex.submit(picarta),
            ex.submit(geoestimation),
            ex.submit(search4faces),
        ]
        for f in as_completed(futures):
            try:
                f.result()
            except Exception as e:
                logger.debug(f"Photo analyzer error: {e}")

    print_summary(results, f"Фото {os.path.basename(image_path)}")
