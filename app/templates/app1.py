import os
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

# -----------------------------
# File Info
def get_file_info(image_path):
    try:
        file_info = {}
        file_info["File Name"] = os.path.basename(image_path)
        file_info["File Size (KB)"] = round(os.path.getsize(image_path) / 1024, 2)

        with Image.open(image_path) as img:
            file_info["File Type"] = os.path.splitext(image_path)[1].replace(".", "").upper()
            file_info["Format"] = img.format
            file_info["Mode"] = img.mode
            file_info["Width"] = img.width
            file_info["Height"] = img.height

        return file_info
    except Exception as e:
        print("Error reading file info:", e)
        return {}

# -----------------------------
# EXIF Data (only necessary fields)
def get_exif_data(image_path):
    try:
        image = Image.open(image_path)
        exif_data = {}
        info = image._getexif()

        required_tags = [
            "ImageWidth", "ImageLength", "Software", "DateTime",
            "Make", "Model", "Orientation", "YCbCrPositioning",
            "XResolution", "YResolution"
        ]

        if info:
            for tag, value in info.items():
                tag_name = TAGS.get(tag, tag)
                if tag_name in required_tags:
                    exif_data[tag_name] = value
        return exif_data
    except Exception as e:
        print("Error reading EXIF data:", e)
        return {}

# -----------------------------
# GPS Info
def get_gps_info(image_path):
    try:
        image = Image.open(image_path)
        exif_data = image._getexif()
        if not exif_data:
            return None

        gps_info = {}
        for tag, value in exif_data.items():
            tag_name = TAGS.get(tag)
            if tag_name == "GPSInfo":
                for t in value:
                    sub_tag = GPSTAGS.get(t, t)
                    gps_info[sub_tag] = value[t]

        if not gps_info:
            return None

        # Convert IFDRational to float
        def rational_to_float(r):
            try:
                return float(r.numerator) / float(r.denominator)
            except:
                return float(r)

        # Convert coordinates to decimal degrees
        def convert_to_degrees(coord):
            d = rational_to_float(coord[0])
            m = rational_to_float(coord[1])
            s = rational_to_float(coord[2])
            return d + (m / 60.0) + (s / 3600.0)

        lat = convert_to_degrees(gps_info["GPSLatitude"])
        if gps_info["GPSLatitudeRef"] != "N":
            lat = -lat

        lon = convert_to_degrees(gps_info["GPSLongitude"])
        if gps_info["GPSLongitudeRef"] != "E":
            lon = -lon

        return {"Latitude": lat, "Longitude": lon,
                "Google Maps": f"https://maps.google.com/?q={lat},{lon}"}

    except Exception as e:
        print("❌ Error reading GPS info:", e)
        return None

# -----------------------------
# Example Usage
image_file = r"IMG-20240904-WA0010.jpg"  # Replace with your image path

# File Info
file_info = get_file_info(image_file)
print("\n--- File Info ---")
for k, v in file_info.items():
    print(f"{k}: {v}")

# EXIF Data
exif_data = get_exif_data(image_file)
print("\n--- EXIF Data ---")
for k, v in exif_data.items():
    print(f"{k}: {v}")

# GPS Location
gps_data = get_gps_info(image_file)
print("\n--- GPS Location ---")
if gps_data:
    for k, v in gps_data.items():
        print(f"{k}: {v}")
else:
    print("No GPS location found in this image.")









