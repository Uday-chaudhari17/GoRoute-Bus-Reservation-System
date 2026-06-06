import os
import re
import secrets
import uuid
import logging
from datetime import date, datetime, time, timedelta
from decimal import Decimal
from functools import wraps
from logging.handlers import RotatingFileHandler

import mysql.connector
from flask import (
    abort,
    Flask,
    Response,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from mysql.connector import Error, IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash

STARTUP_ERROR = None
RATE_LIMIT_BUCKETS = {}


def load_local_env(path=".env"):
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as env_file:
        for raw_line in env_file:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


load_local_env()
APP_ENV = os.getenv("APP_ENV", "development").lower()
IS_PRODUCTION = APP_ENV == "production"

app = Flask(__name__)

secret_key = os.getenv("FLASK_SECRET_KEY")
if not secret_key:
    if IS_PRODUCTION:
        raise RuntimeError("FLASK_SECRET_KEY is required in production.")
    secret_key = secrets.token_hex(32)

app.secret_key = secret_key
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_PRODUCTION,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)


def setup_logging():
    os.makedirs("logs", exist_ok=True)
    file_handler = RotatingFileHandler("logs/app.log", maxBytes=1_000_000, backupCount=3)
    file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)


setup_logging()


def get_db():
    db_password = os.getenv("DB_PASSWORD")
    if IS_PRODUCTION and not db_password:
        raise RuntimeError("DB_PASSWORD is required in production.")
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER", "root"),
        password=db_password or "",
        database=os.getenv("DB_NAME", "bus_reservation"),
        autocommit=False,
    )


def fetch_all(query, params=None):
    db = get_db()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute(query, params or ())
        return cursor.fetchall()
    finally:
        cursor.close()
        db.close()


def fetch_one(query, params=None):
    rows = fetch_all(query, params)
    return rows[0] if rows else None


def execute_query(query, params=None, many=False):
    db = get_db()
    cursor = db.cursor()
    try:
        if many:
            cursor.executemany(query, params or [])
        else:
            cursor.execute(query, params or ())
        db.commit()
        return cursor.lastrowid
    finally:
        cursor.close()
        db.close()


def get_csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def request_fingerprint():
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    ip_address = forwarded_for.split(",")[0].strip() if forwarded_for else request.remote_addr
    return ip_address or "unknown"


def is_rate_limited(scope, limit, seconds):
    now = datetime.now()
    bucket_key = (scope, request_fingerprint())
    attempts = [
        attempt_time
        for attempt_time in RATE_LIMIT_BUCKETS.get(bucket_key, [])
        if (now - attempt_time).total_seconds() < seconds
    ]
    if len(attempts) >= limit:
        RATE_LIMIT_BUCKETS[bucket_key] = attempts
        return True
    attempts.append(now)
    RATE_LIMIT_BUCKETS[bucket_key] = attempts
    return False


@app.before_request
def protect_requests():
    g.csrf_token = get_csrf_token()
    if request.method == "POST":
        submitted_token = request.form.get("csrf_token") or request.headers.get("X-CSRFToken")
        if not submitted_token or not secrets.compare_digest(submitted_token, session.get("csrf_token", "")):
            app.logger.warning("CSRF validation failed for %s from %s", request.path, request_fingerprint())
            abort(400)

    rate_rules = {
        ("login", "POST"): (5, 60),
        ("register", "POST"): (5, 60),
        ("seats", "POST"): (20, 60),
        ("payment", "POST"): (10, 60),
        ("submit_feedback", "POST"): (10, 60),
        ("cancel", "POST"): (8, 60),
    }
    rule = rate_rules.get((request.endpoint, request.method))
    if rule and is_rate_limited(f"{request.endpoint}:{request.method}", *rule):
        app.logger.warning("Rate limit exceeded for %s from %s", request.endpoint, request_fingerprint())
        flash("Too many attempts. Please wait a minute and try again.", "warning")
        abort(429)


def login_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login to continue.", "warning")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    return wrapped_view


def time_to_string(value):
    if value is None:
        return ""
    if isinstance(value, timedelta):
        total_seconds = int(value.total_seconds())
        hours = (total_seconds // 3600) % 24
        minutes = (total_seconds % 3600) // 60
        return f"{hours:02d}:{minutes:02d}"
    if isinstance(value, time):
        return value.strftime("%H:%M")
    if isinstance(value, datetime):
        return value.strftime("%H:%M")
    if isinstance(value, str):
        parts = value.split(":")
        if len(parts) >= 2:
            return f"{int(parts[0]):02d}:{int(parts[1]):02d}"
    return str(value)


def time_value_to_time(value):
    if isinstance(value, time):
        return value
    if isinstance(value, datetime):
        return value.time()
    if isinstance(value, timedelta):
        seconds = int(value.total_seconds())
        hours = (seconds // 3600) % 24
        minutes = (seconds % 3600) // 60
        return time(hour=hours, minute=minutes)
    if isinstance(value, str):
        try:
            return datetime.strptime(value[:5], "%H:%M").time()
        except ValueError:
            pass
    return time(hour=0, minute=0)


def date_value(value):
    if isinstance(value, date):
        return value
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, str):
        try:
            return datetime.strptime(value, "%Y-%m-%d").date()
        except ValueError:
            return datetime.now().date()
    return datetime.now().date()


def default_journey_date():
    return datetime.now().strftime("%Y-%m-%d")


def positive_int(value, default=0):
    try:
        parsed = int(value)
        return parsed if parsed > 0 else default
    except (TypeError, ValueError):
        return default


def normalize_bus(bus):
    if not bus:
        return bus
    bus["departure_time_text"] = time_to_string(bus.get("departure_time"))
    bus["arrival_time_text"] = time_to_string(bus.get("arrival_time"))
    bus["fare_text"] = f"{Decimal(bus.get('fare', 0)).quantize(Decimal('0.01'))}"
    bus["rating_text"] = f"{Decimal(bus.get('rating', 0)).quantize(Decimal('0.0'))}"
    return bus


def normalize_booking(booking):
    if not booking:
        return booking
    booking["journey_date_text"] = date_value(booking.get("journey_date")).strftime("%d %b %Y")
    booking["booked_at_text"] = (
        booking["booked_at"].strftime("%d %b %Y %H:%M")
        if isinstance(booking.get("booked_at"), datetime)
        else str(booking.get("booked_at", ""))
    )
    booking["departure_time_text"] = time_to_string(booking.get("departure_time"))
    booking["arrival_time_text"] = time_to_string(booking.get("arrival_time"))
    booking["total_fare_text"] = f"{Decimal(booking.get('total_fare', 0)).quantize(Decimal('0.01'))}"
    return booking


def get_departure_slot(value):
    dep_time = time_value_to_time(value)
    hour = dep_time.hour
    if 5 <= hour < 12:
        return "Morning"
    if 12 <= hour < 17:
        return "Afternoon"
    if 17 <= hour < 22:
        return "Evening"
    return "Night"


def build_bus_catalog():
    cities = [
        "Pune",
        "Mumbai",
        "Nashik",
        "Bangalore",
        "Chennai",
        "Coimbatore",
        "Hyderabad",
        "Vijayawada",
        "Warangal",
        "Mysore",
        "Delhi",
        "Jaipur",
    ]
    operators = [
        ("RedLine Travels", "Private"),
        ("GoRoute Prime", "Private"),
        ("InterCity Express", "Private"),
        ("CityLink Roadways", "Private"),
    ]
    service_templates = [
        ("AC Seater", 40, 1.18, "WiFi, Charging Point, Live Tracking, Water Bottle", "06:15:00"),
        ("Non AC Seater", 44, 0.86, "Charging Point, Live Tracking, Budget Fare", "13:30:00"),
        ("AC Sleeper", 36, 1.42, "Blanket, Charging Point, Live Tracking, Reading Light", "21:15:00"),
    ]
    catalog = [
        ("GR101", "GoRoute Express", "GoRoute Prime", "Private", "Pune", "Mumbai", 40, 40, 799.00, "06:30:00", "10:15:00", "AC Seater", 4.6, "WiFi, Charging Point, Water Bottle"),
        ("GR102", "Night Rider", "RedLine Travels", "Private", "Bangalore", "Chennai", 36, 36, 1099.00, "21:00:00", "05:45:00", "AC Sleeper", 4.8, "Blanket, Charging Point, Live Tracking"),
        ("GR103", "Royal Cruiser", "InterCity Express", "Private", "Delhi", "Jaipur", 40, 40, 699.00, "07:15:00", "12:00:00", "Non AC Seater", 4.3, "Air Suspension, Water Bottle"),
        ("GR104", "Metro Link", "GoRoute Prime", "Private", "Hyderabad", "Vijayawada", 40, 40, 649.00, "09:30:00", "15:00:00", "AC Seater", 4.4, "Live Tracking, Charging Point"),
        ("GR105", "Sunrise Sleeper", "CityLink Roadways", "Private", "Chennai", "Coimbatore", 36, 36, 949.00, "23:00:00", "06:30:00", "AC Sleeper", 4.7, "Blanket, Snacks"),
    ]

    for source_index, source in enumerate(cities, start=1):
        for destination_index, destination in enumerate(cities, start=1):
            if source == destination:
                continue
            distance_factor = abs(source_index - destination_index) + 2
            base_fare = 260 + distance_factor * 85
            travel_minutes = 150 + distance_factor * 55
            for service_index, (bus_type, seats, multiplier, amenities, departure) in enumerate(service_templates, start=1):
                operator_name, operator_type = operators[(source_index + destination_index + service_index) % len(operators)]
                departure_time = time_value_to_time(departure)
                arrival_dt = datetime.combine(datetime.today(), departure_time) + timedelta(minutes=travel_minutes + service_index * 20)
                route_code = f"GR{source_index:02d}{destination_index:02d}{service_index}"
                bus_name = f"{operator_name.split()[0]} {destination} {bus_type.replace('Non AC ', '')}"
                fare = Decimal(str(base_fare * multiplier)).quantize(Decimal("1"))
                rating = Decimal("4.1") + Decimal(str(((source_index + destination_index + service_index) % 8) / 10))
                catalog.append(
                    (
                        route_code,
                        bus_name,
                        operator_name,
                        operator_type,
                        source,
                        destination,
                        seats,
                        seats,
                        fare,
                        departure,
                        arrival_dt.strftime("%H:%M:%S"),
                        bus_type,
                        min(rating, Decimal("4.9")),
                        amenities,
                    )
                )
    return catalog


def ensure_schema():
    db = get_db()
    cursor = db.cursor(buffered=True)
    try:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                user_id INT PRIMARY KEY AUTO_INCREMENT,
                name VARCHAR(100) NOT NULL,
                email VARCHAR(100) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS buses (
                bus_id INT PRIMARY KEY AUTO_INCREMENT,
                route_code VARCHAR(20) DEFAULT NULL,
                bus_name VARCHAR(100) NOT NULL,
                operator_name VARCHAR(100) DEFAULT 'GoRoute',
                operator_type VARCHAR(20) DEFAULT 'Private',
                source VARCHAR(100) NOT NULL,
                destination VARCHAR(100) NOT NULL,
                total_seats INT NOT NULL DEFAULT 40,
                available_seats INT NOT NULL DEFAULT 40,
                fare DECIMAL(10,2) NOT NULL DEFAULT 499.00,
                departure_time TIME DEFAULT '08:00:00',
                arrival_time TIME DEFAULT '12:00:00',
                bus_type VARCHAR(50) DEFAULT 'AC Seater',
                rating DECIMAL(3,1) DEFAULT 4.0,
                amenities VARCHAR(255) DEFAULT 'WiFi, Charging Point'
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS bus_seats (
                seat_id INT PRIMARY KEY AUTO_INCREMENT,
                bus_id INT NOT NULL,
                seat_number VARCHAR(10) NOT NULL,
                status ENUM('available', 'booked') DEFAULT 'available',
                UNIQUE KEY uniq_bus_seat (bus_id, seat_number),
                CONSTRAINT fk_bus_seats_bus
                    FOREIGN KEY (bus_id) REFERENCES buses(bus_id) ON DELETE CASCADE
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS bus_stops (
                stop_id INT PRIMARY KEY AUTO_INCREMENT,
                bus_id INT NOT NULL,
                stop_name VARCHAR(100) NOT NULL,
                stop_order INT NOT NULL,
                arrival_offset_mins INT NOT NULL DEFAULT 0,
                departure_offset_mins INT NOT NULL DEFAULT 0,
                UNIQUE KEY uniq_bus_stop (bus_id, stop_order),
                FOREIGN KEY (bus_id) REFERENCES buses(bus_id) ON DELETE CASCADE
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS bookings (
                booking_id INT PRIMARY KEY AUTO_INCREMENT,
                booking_reference VARCHAR(20) NOT NULL UNIQUE,
                user_id INT NOT NULL,
                bus_id INT NOT NULL,
                passenger_name VARCHAR(100) DEFAULT 'Passenger',
                emergency_contact VARCHAR(30) DEFAULT 'Not Provided',
                seat_numbers VARCHAR(255) NOT NULL,
                seats_booked INT NOT NULL,
                journey_date DATE NOT NULL,
                total_fare DECIMAL(10,2) NOT NULL DEFAULT 0,
                ticket_status ENUM('CONFIRMED', 'CANCELLED') DEFAULT 'CONFIRMED',
                payment_status ENUM('SUCCESS', 'FAILED', 'REFUNDED') DEFAULT 'SUCCESS',
                payment_method VARCHAR(20) DEFAULT 'UPI',
                booked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                cancelled_at TIMESTAMP NULL DEFAULT NULL,
                FOREIGN KEY (user_id) REFERENCES users(user_id),
                FOREIGN KEY (bus_id) REFERENCES buses(bus_id)
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS payments (
                payment_id INT PRIMARY KEY AUTO_INCREMENT,
                booking_id INT NOT NULL,
                amount DECIMAL(10,2) NOT NULL,
                method VARCHAR(20) NOT NULL,
                provider_reference VARCHAR(40) NOT NULL,
                payment_state ENUM('SUCCESS', 'FAILED', 'REFUNDED') DEFAULT 'SUCCESS',
                paid_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (booking_id) REFERENCES bookings(booking_id) ON DELETE CASCADE
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS feedback (
                feedback_id INT PRIMARY KEY AUTO_INCREMENT,
                booking_id INT NOT NULL,
                user_id INT NOT NULL,
                bus_id INT NOT NULL,
                rating INT NOT NULL,
                comments VARCHAR(500) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY uniq_feedback_booking (booking_id, user_id),
                FOREIGN KEY (booking_id) REFERENCES bookings(booking_id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
                FOREIGN KEY (bus_id) REFERENCES buses(bus_id) ON DELETE CASCADE
            )
            """
        )

        migration_specs = {
            "buses": {
                "route_code": "ALTER TABLE buses ADD COLUMN route_code VARCHAR(20) DEFAULT NULL",
                "operator_name": "ALTER TABLE buses ADD COLUMN operator_name VARCHAR(100) DEFAULT 'GoRoute'",
                "operator_type": "ALTER TABLE buses ADD COLUMN operator_type VARCHAR(20) DEFAULT 'Private'",
                "amenities": "ALTER TABLE buses ADD COLUMN amenities VARCHAR(255) DEFAULT 'WiFi, Charging Point'",
                "departure_time": "ALTER TABLE buses ADD COLUMN departure_time TIME DEFAULT '08:00:00'",
                "arrival_time": "ALTER TABLE buses ADD COLUMN arrival_time TIME DEFAULT '12:00:00'",
                "bus_type": "ALTER TABLE buses ADD COLUMN bus_type VARCHAR(50) DEFAULT 'AC Seater'",
                "rating": "ALTER TABLE buses ADD COLUMN rating DECIMAL(3,1) DEFAULT 4.0",
            },
            "bookings": {
                "booking_reference": "ALTER TABLE bookings ADD COLUMN booking_reference VARCHAR(20) NULL",
                "passenger_name": "ALTER TABLE bookings ADD COLUMN passenger_name VARCHAR(100) DEFAULT 'Passenger'",
                "emergency_contact": "ALTER TABLE bookings ADD COLUMN emergency_contact VARCHAR(30) DEFAULT 'Not Provided'",
                "seat_numbers": "ALTER TABLE bookings ADD COLUMN seat_numbers VARCHAR(255) NOT NULL DEFAULT ''",
                "journey_date": "ALTER TABLE bookings ADD COLUMN journey_date DATE NULL",
                "total_fare": "ALTER TABLE bookings ADD COLUMN total_fare DECIMAL(10,2) NOT NULL DEFAULT 0",
                "ticket_status": "ALTER TABLE bookings ADD COLUMN ticket_status ENUM('CONFIRMED', 'CANCELLED') DEFAULT 'CONFIRMED'",
                "payment_status": "ALTER TABLE bookings ADD COLUMN payment_status ENUM('SUCCESS', 'FAILED', 'REFUNDED') DEFAULT 'SUCCESS'",
                "payment_method": "ALTER TABLE bookings ADD COLUMN payment_method VARCHAR(20) DEFAULT 'UPI'",
                "booked_at": "ALTER TABLE bookings ADD COLUMN booked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
                "cancelled_at": "ALTER TABLE bookings ADD COLUMN cancelled_at TIMESTAMP NULL DEFAULT NULL",
            },
            "users": {
                "created_at": "ALTER TABLE users ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
            },
        }

        for table_name, columns in migration_specs.items():
            for column, ddl in columns.items():
                cursor.execute(f"SHOW COLUMNS FROM {table_name} LIKE %s", (column,))
                if not cursor.fetchone():
                    cursor.execute(ddl)

        index_specs = [
            ("buses", "idx_buses_route_search", "CREATE INDEX idx_buses_route_search ON buses(source, destination, bus_type, fare, rating)"),
            ("buses", "idx_buses_route_code", "CREATE INDEX idx_buses_route_code ON buses(route_code)"),
            ("bus_seats", "idx_bus_seats_status", "CREATE INDEX idx_bus_seats_status ON bus_seats(bus_id, status)"),
            ("bookings", "idx_bookings_user_status", "CREATE INDEX idx_bookings_user_status ON bookings(user_id, ticket_status, booked_at)"),
        ]
        for table_name, index_name, ddl in index_specs:
            cursor.execute(f"SHOW INDEX FROM {table_name} WHERE Key_name=%s", (index_name,))
            if not cursor.fetchone():
                cursor.execute(ddl)

        cursor.execute(
            """
            UPDATE buses
            SET operator_type='Private',
                amenities=REPLACE(amenities, 'Government Service, ', '')
            WHERE operator_type='Government'
            """
        )

        cursor.execute("SHOW COLUMNS FROM users LIKE 'password'")
        password_column = cursor.fetchone()
        if password_column:
            column_type = str(password_column[1]).lower()
            match = re.search(r"varchar\((\d+)\)", column_type)
            if match and int(match.group(1)) < 255:
                cursor.execute("ALTER TABLE users MODIFY password VARCHAR(255) NOT NULL")

        cursor.execute("SHOW TABLES LIKE 'bus_stops'")
        if not cursor.fetchone():
            cursor.execute(
                """
                CREATE TABLE bus_stops (
                    stop_id INT PRIMARY KEY AUTO_INCREMENT,
                    bus_id INT NOT NULL,
                    stop_name VARCHAR(100) NOT NULL,
                    stop_order INT NOT NULL,
                    arrival_offset_mins INT NOT NULL DEFAULT 0,
                    departure_offset_mins INT NOT NULL DEFAULT 0,
                    UNIQUE KEY uniq_bus_stop (bus_id, stop_order),
                    FOREIGN KEY (bus_id) REFERENCES buses(bus_id) ON DELETE CASCADE
                )
                """
            )
        cursor.execute("SHOW TABLES LIKE 'feedback'")
        if not cursor.fetchone():
            cursor.execute(
                """
                CREATE TABLE feedback (
                    feedback_id INT PRIMARY KEY AUTO_INCREMENT,
                    booking_id INT NOT NULL,
                    user_id INT NOT NULL,
                    bus_id INT NOT NULL,
                    rating INT NOT NULL,
                    comments VARCHAR(500) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE KEY uniq_feedback_booking (booking_id, user_id),
                    FOREIGN KEY (booking_id) REFERENCES bookings(booking_id) ON DELETE CASCADE,
                    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
                    FOREIGN KEY (bus_id) REFERENCES buses(bus_id) ON DELETE CASCADE
                )
                """
            )

        cursor.execute("SELECT route_code FROM buses WHERE route_code IS NOT NULL")
        existing_route_codes = {row[0] for row in cursor.fetchall()}
        seed_buses = [row for row in build_bus_catalog() if row[0] not in existing_route_codes]
        if seed_buses:
            cursor.executemany(
                """
                INSERT INTO buses(
                    route_code, bus_name, operator_name, operator_type, source, destination, total_seats,
                    available_seats, fare, departure_time, arrival_time, bus_type, rating, amenities
                )
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                seed_buses,
            )

        stop_map = {
            "GR101": [("Pune", 0, 0), ("Lonavala", 80, 90), ("Panvel", 155, 165), ("Mumbai", 225, 225)],
            "GR102": [("Bangalore", 0, 0), ("Hosur", 45, 55), ("Vellore", 180, 190), ("Chennai", 525, 525)],
            "GR103": [("Delhi", 0, 0), ("Gurgaon", 35, 45), ("Neemrana", 150, 160), ("Jaipur", 285, 285)],
            "GR104": [("Hyderabad", 0, 0), ("Suryapet", 110, 120), ("Nandigama", 235, 245), ("Vijayawada", 330, 330)],
            "GR105": [("Chennai", 0, 0), ("Villupuram", 140, 150), ("Salem", 310, 320), ("Coimbatore", 450, 450)],
            "GS201": [("Pune", 0, 0), ("Chakan", 40, 50), ("Sinnar", 185, 195), ("Nashik", 240, 240)],
            "GS202": [("Nashik", 0, 0), ("Igatpuri", 80, 90), ("Thane", 240, 250), ("Mumbai", 270, 270)],
            "GS203": [("Hyderabad", 0, 0), ("Ghatkesar", 35, 45), ("Jangaon", 110, 120), ("Warangal", 195, 195)],
            "GS204": [("Bangalore", 0, 0), ("Ramanagara", 55, 65), ("Mandya", 140, 150), ("Mysore", 180, 180)],
        }
        cursor.execute("SELECT bus_id, route_code, source, destination, total_seats, departure_time, arrival_time FROM buses")
        route_lookup = cursor.fetchall()
        for bus_id, route_code, source, destination, total_seats, departure_time, arrival_time in route_lookup:
            cursor.execute("SELECT COUNT(*) FROM bus_seats WHERE bus_id=%s", (bus_id,))
            existing_seats = cursor.fetchone()[0]
            if existing_seats < total_seats:
                seat_rows = [(bus_id, str(index)) for index in range(existing_seats + 1, total_seats + 1)]
                cursor.executemany(
                    "INSERT IGNORE INTO bus_seats(bus_id, seat_number) VALUES(%s, %s)",
                    seat_rows,
                )

            cursor.execute("SELECT COUNT(*) FROM bus_stops WHERE bus_id=%s", (bus_id,))
            existing_stops = cursor.fetchone()[0]
            if existing_stops == 0:
                if route_code in stop_map:
                    stops = stop_map[route_code]
                else:
                    dep_time = time_value_to_time(departure_time)
                    arr_time = time_value_to_time(arrival_time)
                    dep_dt = datetime.combine(datetime.today(), dep_time)
                    arr_dt = datetime.combine(datetime.today(), arr_time)
                    if arr_dt <= dep_dt:
                        arr_dt += timedelta(days=1)
                    total_mins = max(int((arr_dt - dep_dt).total_seconds() // 60), 120)
                    stops = [
                        (source, 0, 0),
                        (f"{source}-{destination} Food Plaza", total_mins // 2, total_mins // 2 + 12),
                        (destination, total_mins, total_mins),
                    ]
                stop_rows = [
                    (bus_id, stop_name, order_index + 1, arrival_offset, departure_offset)
                    for order_index, (stop_name, arrival_offset, departure_offset) in enumerate(stops)
                ]
                cursor.executemany(
                    """
                    INSERT INTO bus_stops(bus_id, stop_name, stop_order, arrival_offset_mins, departure_offset_mins)
                    VALUES(%s,%s,%s,%s,%s)
                    """,
                    stop_rows,
                )

        cursor.execute("UPDATE bookings SET journey_date = CURDATE() WHERE journey_date IS NULL")
        cursor.execute(
            """
            UPDATE bookings
            SET booking_reference = CONCAT('GR', LPAD(booking_id, 6, '0'))
            WHERE booking_reference IS NULL OR booking_reference = ''
            """
        )
        cursor.execute(
            """
            UPDATE bookings
            SET passenger_name = 'Passenger'
            WHERE passenger_name IS NULL OR passenger_name = ''
            """
        )
        cursor.execute(
            """
            UPDATE bookings
            SET emergency_contact = 'Not Provided'
            WHERE emergency_contact IS NULL OR emergency_contact = ''
            """
        )
        db.commit()
    finally:
        cursor.close()
        db.close()


def calculate_pricing(bus_fare, seat_count, journey_date):
    base_total = Decimal(bus_fare) * seat_count
    weekend_surge = Decimal("0.15") if journey_date.weekday() >= 5 else Decimal("0.00")
    group_discount = Decimal("0.10") if seat_count >= 4 else Decimal("0.00")
    surge_amount = (base_total * weekend_surge).quantize(Decimal("0.01"))
    discount_amount = (base_total * group_discount).quantize(Decimal("0.01"))
    total = (base_total + surge_amount - discount_amount).quantize(Decimal("0.01"))
    return {
        "base_total": base_total.quantize(Decimal("0.01")),
        "weekend_surge": surge_amount,
        "group_discount": discount_amount,
        "total": total,
    }


def build_recommendations(user_id):
    rows = fetch_all(
        """
        SELECT
            bu.bus_id, bu.route_code, bu.bus_name, bu.operator_name, bu.operator_type, bu.source, bu.destination,
            bu.available_seats, bu.total_seats, bu.fare, bu.departure_time, bu.arrival_time,
            bu.bus_type, bu.rating, bu.amenities, COUNT(*) AS route_hits
        FROM bookings b
        JOIN buses bu ON bu.bus_id = b.bus_id
        WHERE b.user_id = %s AND b.ticket_status = 'CONFIRMED'
        GROUP BY bu.bus_id, bu.route_code, bu.bus_name, bu.operator_name, bu.operator_type, bu.source,
                 bu.destination, bu.available_seats, bu.total_seats, bu.fare, bu.departure_time,
                 bu.arrival_time, bu.bus_type, bu.rating, bu.amenities
        ORDER BY route_hits DESC, bu.rating DESC
        LIMIT 3
        """,
        (user_id,),
    )
    if not rows:
        rows = fetch_all(
            """
            SELECT
                bus_id, route_code, bus_name, operator_name, operator_type, source, destination,
                available_seats, total_seats, fare, departure_time, arrival_time, bus_type, rating, amenities
            FROM buses
            ORDER BY rating DESC, available_seats DESC
            LIMIT 3
            """
        )
    for bus in rows:
        normalize_bus(bus)
    return rows


def build_route_insights():
    return fetch_all(
        """
        SELECT CONCAT(source, ' to ', destination) AS route_name, COUNT(*) AS route_count
        FROM buses
        GROUP BY source, destination
        ORDER BY route_count DESC, route_name ASC
        LIMIT 6
        """
    )


def get_recent_feedback():
    rows = fetch_all(
        """
        SELECT f.rating, f.comments, f.created_at, u.name, bu.bus_name
        FROM feedback f
        JOIN users u ON u.user_id = f.user_id
        JOIN buses bu ON bu.bus_id = f.bus_id
        ORDER BY f.created_at DESC
        LIMIT 6
        """
    )
    for row in rows:
        row["created_at_text"] = row["created_at"].strftime("%d %b %Y") if isinstance(row.get("created_at"), datetime) else ""
    return rows


def get_ticket_payload(booking):
    return (
        f"BOOKING:{booking['booking_reference']}|BUS:{booking['bus_name']}|"
        f"PASSENGER:{booking['passenger_name']}|ROUTE:{booking['source']}-{booking['destination']}|"
        f"SEATS:{booking['seat_numbers']}|DATE:{booking['journey_date_text']}"
    )


def get_bus_stops(bus_id):
    rows = fetch_all(
        """
        SELECT stop_name, stop_order, arrival_offset_mins, departure_offset_mins
        FROM bus_stops
        WHERE bus_id=%s
        ORDER BY stop_order
        """,
        (bus_id,),
    )
    return rows


def add_tracking_data(bus, journey_date=None):
    journey_date = journey_date or datetime.now().date()
    stops = get_bus_stops(bus["bus_id"])
    now = datetime.now()
    dep_dt = datetime.combine(journey_date, time_value_to_time(bus["departure_time"]))
    arr_dt = datetime.combine(journey_date, time_value_to_time(bus["arrival_time"]))
    if arr_dt <= dep_dt:
        arr_dt += timedelta(days=1)
    total_seconds = max((arr_dt - dep_dt).total_seconds(), 1)

    if journey_date > now.date():
        progress = 0
        status = "Scheduled"
        summary = f"Departs at {time_to_string(bus['departure_time'])}"
        current_stop = bus["source"]
        next_stop = stops[1]["stop_name"] if len(stops) > 1 else bus["destination"]
    elif now < dep_dt:
        progress = 0
        status = "Boarding Soon"
        mins = int((dep_dt - now).total_seconds() // 60)
        summary = f"Departs in {max(mins, 0)} mins"
        current_stop = bus["source"]
        next_stop = stops[1]["stop_name"] if len(stops) > 1 else bus["destination"]
    elif now >= arr_dt:
        progress = 100
        status = "Completed"
        summary = "Reached destination"
        current_stop = bus["destination"]
        next_stop = "Trip closed"
    else:
        progress = int(((now - dep_dt).total_seconds() / total_seconds) * 100)
        progress = min(max(progress, 1), 99)
        current_stop = bus["source"]
        next_stop = bus["destination"]
        status = "On Time"
        summary = f"{progress}% of route completed"
        for index, stop in enumerate(stops):
            stop_time = dep_dt + timedelta(minutes=stop["arrival_offset_mins"])
            if now >= stop_time:
                current_stop = stop["stop_name"]
                next_stop = stops[index + 1]["stop_name"] if index + 1 < len(stops) else bus["destination"]
            else:
                next_stop = stop["stop_name"]
                break
        eta_minutes = int((arr_dt - now).total_seconds() // 60)
        summary = f"{progress}% complete, ETA {max(eta_minutes, 0)} mins"

    bus["tracking_progress"] = progress
    bus["tracking_status"] = status
    bus["tracking_text"] = summary
    bus["current_stop"] = current_stop
    bus["next_stop"] = next_stop
    bus["departure_slot"] = get_departure_slot(bus["departure_time"])
    bus["stops"] = stops
    normalize_bus(bus)
    return bus


def find_alternate_routes(source, destination, journey_date, operator_type=None):
    query = """
        SELECT
            b1.bus_id AS leg1_bus_id, b1.bus_name AS leg1_bus_name, b1.operator_name AS leg1_operator_name,
            b1.operator_type AS leg1_operator_type, b1.source AS source, b1.destination AS transit_city,
            b1.departure_time AS leg1_departure, b1.arrival_time AS leg1_arrival, b1.fare AS leg1_fare,
            b2.bus_id AS leg2_bus_id, b2.bus_name AS leg2_bus_name, b2.operator_name AS leg2_operator_name,
            b2.operator_type AS leg2_operator_type, b2.destination AS destination,
            b2.departure_time AS leg2_departure, b2.arrival_time AS leg2_arrival, b2.fare AS leg2_fare
        FROM buses b1
        JOIN buses b2 ON b1.destination = b2.source
        WHERE b1.source = %s
          AND b2.destination = %s
          AND b1.bus_id <> b2.bus_id
    """
    params = [source, destination]
    if operator_type:
        query += " AND b1.operator_type = %s AND b2.operator_type = %s"
        params.extend([operator_type, operator_type])
    query += " ORDER BY (b1.fare + b2.fare) ASC, b1.rating DESC, b2.rating DESC LIMIT 4"
    rows = fetch_all(query, tuple(params))
    suggestions = []
    for row in rows:
        leg1_departure = time_value_to_time(row["leg1_departure"])
        leg1_arrival = time_value_to_time(row["leg1_arrival"])
        leg2_departure = time_value_to_time(row["leg2_departure"])
        layover = (
            datetime.combine(journey_date, leg2_departure) - datetime.combine(journey_date, leg1_arrival)
        ).total_seconds() // 60
        if layover < 20:
            continue
        suggestion = {
            "source": row["source"],
            "transit_city": row["transit_city"],
            "destination": row["destination"],
            "total_fare": (Decimal(row["leg1_fare"]) + Decimal(row["leg2_fare"])).quantize(Decimal("0.01")),
            "layover_minutes": int(layover),
            "leg1": {
                "bus_id": row["leg1_bus_id"],
                "bus_name": row["leg1_bus_name"],
                "operator_name": row["leg1_operator_name"],
                "operator_type": row["leg1_operator_type"],
                "departure_time_text": time_to_string(row["leg1_departure"]),
                "arrival_time_text": time_to_string(row["leg1_arrival"]),
                "fare_text": f"{Decimal(row['leg1_fare']).quantize(Decimal('0.01'))}",
            },
            "leg2": {
                "bus_id": row["leg2_bus_id"],
                "bus_name": row["leg2_bus_name"],
                "operator_name": row["leg2_operator_name"],
                "operator_type": row["leg2_operator_type"],
                "departure_time_text": time_to_string(row["leg2_departure"]),
                "arrival_time_text": time_to_string(row["leg2_arrival"]),
                "fare_text": f"{Decimal(row['leg2_fare']).quantize(Decimal('0.01'))}",
            },
        }
        suggestions.append(suggestion)
    return suggestions


def get_booking_or_none(booking_id, user_id):
    booking = fetch_one(
        """
        SELECT
            b.booking_id, b.booking_reference, b.passenger_name, b.emergency_contact, b.seat_numbers,
            b.seats_booked, b.journey_date, b.total_fare, b.ticket_status, b.payment_status,
            b.payment_method, b.booked_at, b.cancelled_at,
            bu.bus_id, bu.route_code, bu.bus_name, bu.operator_name, bu.operator_type, bu.source,
            bu.destination, bu.departure_time, bu.arrival_time, bu.bus_type, bu.amenities
        FROM bookings b
        JOIN buses bu ON bu.bus_id = b.bus_id
        WHERE b.booking_id=%s AND b.user_id=%s
        """,
        (booking_id, user_id),
    )
    if booking:
        normalize_booking(booking)
    return booking


def is_password_match(stored_password, raw_password):
    if not stored_password:
        return False
    if stored_password.startswith("pbkdf2:") or stored_password.startswith("scrypt:"):
        return check_password_hash(stored_password, raw_password)
    return stored_password == raw_password


def migrate_plain_password(user, raw_password):
    if user and user.get("password") == raw_password:
        execute_query(
            "UPDATE users SET password=%s WHERE user_id=%s",
            (generate_password_hash(raw_password), user["user_id"]),
        )


def validate_registration(name, email, password):
    if not name or len(name) < 2:
        return "Enter a valid full name."
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return "Enter a valid email address."
    if len(password) < 6:
        return "Password must be at least 6 characters long."
    return None


def get_search_context(operator_type=None):
    sources = [row["source"] for row in fetch_all("SELECT DISTINCT source FROM buses ORDER BY source")]
    destinations = [row["destination"] for row in fetch_all("SELECT DISTINCT destination FROM buses ORDER BY destination")]
    recommendations = build_recommendations(session["user_id"]) if session.get("user_id") else []
    filters = {
        "source": request.values.get("source", ""),
        "destination": request.values.get("destination", ""),
        "journey_date": request.values.get("journey_date", session.get("journey_date", default_journey_date())),
        "bus_type": request.values.get("bus_type", ""),
        "rating": request.values.get("rating", ""),
        "max_fare": request.values.get("max_fare", ""),
        "departure_slot": request.values.get("departure_slot", ""),
        "min_seats": request.values.get("min_seats", ""),
        "operator_type": operator_type or request.values.get("operator_type", ""),
    }
    return sources, destinations, recommendations, filters


def search_buses(filters, forced_operator_type=None):
    if not filters["source"] or not filters["destination"]:
        return []
    query = """
        SELECT
            bus_id, route_code, bus_name, operator_name, operator_type, source, destination,
            available_seats, total_seats, fare, departure_time, arrival_time, bus_type, rating, amenities
        FROM buses
        WHERE source=%s AND destination=%s
    """
    params = [filters["source"], filters["destination"]]
    if filters["rating"]:
        query += " AND rating >= %s"
        params.append(filters["rating"])
    if filters["bus_type"]:
        query += " AND bus_type = %s"
        params.append(filters["bus_type"])
    if filters["max_fare"]:
        query += " AND fare <= %s"
        params.append(filters["max_fare"])
    min_seats = positive_int(filters["min_seats"])
    if min_seats:
        query += " AND available_seats >= %s"
        params.append(min_seats)
    if forced_operator_type or filters["operator_type"]:
        query += " AND operator_type = %s"
        params.append(forced_operator_type or filters["operator_type"])
    query += " ORDER BY rating DESC, fare ASC"
    rows = fetch_all(query, tuple(params))
    journey_date = date_value(filters["journey_date"]) if filters["journey_date"] else datetime.now().date()
    filtered_rows = []
    for row in rows:
        add_tracking_data(row, journey_date)
        row["recommended"] = False
        if filters["departure_slot"] and row["departure_slot"] != filters["departure_slot"]:
            continue
        filtered_rows.append(row)
    return filtered_rows


def build_pdf_bytes(lines):
    def escape_pdf_text(value):
        return str(value).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    stream_lines = [
        "q",
        "0.95 0.98 0.97 rg",
        "36 36 540 770 re f",
        "0.06 0.46 0.43 RG",
        "2 w",
        "36 36 540 770 re S",
        "BT",
        "/F2 22 Tf",
        "0.06 0.46 0.43 rg",
        "54 760 Td",
        "(GoRoute Confirmed Bus Ticket) Tj",
        "/F1 11 Tf",
        "0.09 0.13 0.16 rg",
        "0 -34 Td",
        "16 TL",
    ]
    for line in lines:
        stream_lines.append(f"({escape_pdf_text(line)}) Tj")
        stream_lines.append("T*")
    stream_lines.extend(
        [
            "0 -14 Td",
            "/F1 9 Tf",
            "(Carry a valid ID proof. This ticket is valid only for the passenger and journey shown above.) Tj",
            "ET",
            "Q",
        ]
    )
    stream_data = "\n".join(stream_lines).encode("latin-1", errors="replace")

    objects = []
    objects.append(b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n")
    objects.append(b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n")
    objects.append(
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] "
        b"/Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> /Contents 6 0 R >> endobj\n"
    )
    objects.append(b"4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n")
    objects.append(b"5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >> endobj\n")
    objects.append(f"6 0 obj << /Length {len(stream_data)} >> stream\n".encode("latin-1") + stream_data + b"\nendstream endobj\n")

    pdf = b"%PDF-1.4\n"
    offsets = [0]
    for obj in objects:
        offsets.append(len(pdf))
        pdf += obj
    xref_start = len(pdf)
    pdf += f"xref\n0 {len(objects) + 1}\n".encode("latin-1")
    pdf += b"0000000000 65535 f \n"
    for offset in offsets[1:]:
        pdf += f"{offset:010d} 00000 n \n".encode("latin-1")
    pdf += (
        f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_start}\n%%EOF".encode("latin-1")
    )
    return pdf


@app.context_processor
def inject_global_data():
    return {
        "current_year": datetime.now().year,
        "today": default_journey_date(),
        "csrf_token": get_csrf_token,
        "startup_error": STARTUP_ERROR,
    }


@app.route("/")
def home():
    routes = build_route_insights()
    top_buses = fetch_all(
        """
        SELECT
            bus_id, route_code, bus_name, operator_name, operator_type, source, destination,
            available_seats, total_seats, fare, departure_time, arrival_time, bus_type, rating, amenities
        FROM buses
        ORDER BY rating DESC, available_seats DESC
        LIMIT 6
        """
    )
    for bus in top_buses:
        add_tracking_data(bus)
    feedbacks = get_recent_feedback()
    return render_template("index.html", routes=routes, top_buses=top_buses, feedbacks=feedbacks)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        validation_error = validate_registration(name, email, password)
        if validation_error:
            flash(validation_error, "danger")
            return render_template("register.html")

        try:
            execute_query(
                "INSERT INTO users(name, email, password) VALUES(%s, %s, %s)",
                (name, email, generate_password_hash(password)),
            )
            app.logger.info("New registration for %s", email)
            flash("Registration successful. Please login to continue.", "success")
            return redirect(url_for("login"))
        except IntegrityError:
            app.logger.info("Duplicate registration attempt for %s", email)
            flash("That email is already registered. Please login instead.", "danger")
        except Error as exc:
            app.logger.exception("Registration failed for %s", email)
            flash(f"Registration failed due to database error: {exc}", "danger")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        try:
            user = fetch_one("SELECT * FROM users WHERE email=%s", (email,))
        except Error as exc:
            flash(f"Login failed due to database error: {exc}", "danger")
            return render_template("login.html")

        if user and is_password_match(user["password"], password):
            migrate_plain_password(user, password)
            session["user_id"] = user["user_id"]
            session["user_name"] = user["name"]
            session.permanent = True
            app.logger.info("Successful login for user_id=%s", user["user_id"])
            flash("Welcome back. Your travel dashboard is ready.", "success")
            return redirect(url_for("search"))

        app.logger.warning("Failed login attempt for %s from %s", email, request_fingerprint())
        flash("Invalid email or password.", "danger")

    return render_template("login.html")


@app.route("/search", methods=["GET", "POST"])
@login_required
def search():
    sources, destinations, recommendations, filters = get_search_context()
    buses = []
    alternate_routes = []
    if request.method == "POST":
        session["journey_date"] = filters["journey_date"]
        session["last_search"] = {"source": filters["source"], "destination": filters["destination"]}
        if date_value(filters["journey_date"]) < datetime.now().date():
            flash("Choose today or a future journey date.", "warning")
        elif filters["source"] == filters["destination"]:
            flash("Source and destination must be different.", "warning")
        else:
            buses = search_buses(filters)
            for bus in buses:
                bus["recommended"] = any(rec["bus_id"] == bus["bus_id"] for rec in recommendations)
            if not buses and filters["source"] and filters["destination"] and filters["journey_date"]:
                alternate_routes = find_alternate_routes(filters["source"], filters["destination"], date_value(filters["journey_date"]))
    return render_template(
        "search.html",
        buses=buses,
        sources=sources,
        destinations=destinations,
        recommendations=recommendations,
        search_filters=filters,
        last_search=session.get("last_search"),
        alternate_routes=alternate_routes,
        page_title="All Buses",
        forced_operator_type="",
    )


@app.route("/timetable", methods=["GET", "POST"])
@login_required
def timetable():
    city = request.form.get("city", request.args.get("city", "")).strip()
    timetable_date = request.form.get("journey_date", request.args.get("journey_date", datetime.now().strftime("%Y-%m-%d")))
    query = """
        SELECT
            bus_id, route_code, bus_name, operator_name, operator_type, source, destination,
            available_seats, total_seats, fare, departure_time, arrival_time, bus_type, rating, amenities
        FROM buses
        WHERE 1=1
    """
    params = []
    if city:
        query += " AND (source=%s OR destination=%s)"
        params.extend([city, city])
    query += " ORDER BY departure_time ASC, source ASC"
    buses = fetch_all(query, tuple(params))
    journey_date = date_value(timetable_date)
    if journey_date < datetime.now().date():
        timetable_date = default_journey_date()
        journey_date = datetime.now().date()
        flash("Showing timetable for today because past dates cannot be booked.", "warning")
    for bus in buses:
        add_tracking_data(bus, journey_date)
    cities = sorted(set([row["source"] for row in fetch_all("SELECT source FROM buses")] + [row["destination"] for row in fetch_all("SELECT destination FROM buses")]))
    return render_template(
        "timetable.html",
        buses=buses,
        cities=cities,
        filters={"city": city, "journey_date": timetable_date},
    )


@app.route("/live-tracking/<int:bus_id>")
@login_required
def live_tracking(bus_id):
    journey_date_raw = request.args.get("journey_date", session.get("journey_date", datetime.now().strftime("%Y-%m-%d")))
    journey_date = date_value(journey_date_raw)
    bus = fetch_one(
        """
        SELECT
            bus_id, route_code, bus_name, operator_name, operator_type, source, destination,
            available_seats, total_seats, fare, departure_time, arrival_time, bus_type, rating, amenities
        FROM buses
        WHERE bus_id=%s
        """,
        (bus_id,),
    )
    if not bus:
        flash("Bus not found.", "danger")
        return redirect(url_for("search"))
    add_tracking_data(bus, journey_date)
    return render_template("live_tracking.html", bus=bus, journey_date_text=journey_date.strftime("%d %b %Y"))


@app.route("/seats/<int:bus_id>", methods=["GET", "POST"])
@login_required
def seats(bus_id):
    requested_journey_date = request.values.get("journey_date")
    if requested_journey_date:
        session["journey_date"] = date_value(requested_journey_date).strftime("%Y-%m-%d")

    bus = fetch_one(
        """
        SELECT
            bus_id, route_code, bus_name, operator_name, operator_type, source, destination,
            available_seats, total_seats, fare, departure_time, arrival_time, bus_type, rating, amenities
        FROM buses
        WHERE bus_id=%s
        """,
        (bus_id,),
    )
    if not bus:
        flash("Bus not found.", "danger")
        return redirect(url_for("search"))
    session.setdefault("journey_date", default_journey_date())
    add_tracking_data(bus, date_value(session.get("journey_date", default_journey_date())))
    bus["layout_class"] = "sleeper-layout" if "Sleeper" in bus.get("bus_type", "") else "seater-layout"
    bus["layout_name"] = "Sleeper coach" if "Sleeper" in bus.get("bus_type", "") else "2 x 2 seater coach"
    seat_rows = fetch_all(
        """
        SELECT seat_id, seat_number, status
        FROM bus_seats
        WHERE bus_id=%s
        ORDER BY CAST(seat_number AS UNSIGNED)
        """,
        (bus_id,),
    )

    if request.method == "POST":
        selected = request.form.getlist("seats")
        if not selected:
            flash("Select at least one available seat.", "danger")
            return redirect(url_for("seats", bus_id=bus_id))

        placeholders = ",".join(["%s"] * len(selected))
        available = fetch_all(
            f"""
            SELECT seat_number
            FROM bus_seats
            WHERE bus_id=%s AND status='available' AND seat_number IN ({placeholders})
            """,
            tuple([bus_id] + selected),
        )
        if len(available) != len(selected):
            flash("One or more selected seats are no longer available.", "danger")
            return redirect(url_for("seats", bus_id=bus_id))

        session["selected_seats"] = sorted(selected, key=lambda value: int(value))
        session["bus_id"] = bus_id
        return redirect(url_for("payment"))

    return render_template("seats.html", bus=bus, seat_rows=seat_rows)


@app.route("/payment", methods=["GET", "POST"])
@login_required
def payment():
    bus_id = session.get("bus_id")
    selected_seats = session.get("selected_seats")
    journey_date_raw = session.get("journey_date")
    if not bus_id or not selected_seats or not journey_date_raw:
        flash("Please search buses and select seats before payment.", "warning")
        return redirect(url_for("search"))

    bus = fetch_one(
        """
        SELECT
            bus_id, route_code, bus_name, operator_name, operator_type, source, destination,
            fare, departure_time, arrival_time, bus_type, rating, amenities, available_seats, total_seats
        FROM buses
        WHERE bus_id=%s
        """,
        (bus_id,),
    )
    if not bus:
        flash("Selected bus is no longer available.", "danger")
        return redirect(url_for("search"))

    journey_date = date_value(journey_date_raw)
    add_tracking_data(bus, journey_date)
    pricing = calculate_pricing(bus["fare"], len(selected_seats), journey_date)

    if request.method == "POST":
        payment_method = request.form.get("payment_method", "")
        payment_outcome = request.form.get("payment_outcome", "")
        passenger_name = request.form.get("passenger_name", "").strip()
        emergency_contact = request.form.get("emergency_contact", "").strip()

        if not passenger_name:
            flash("Passenger name is required.", "danger")
            return render_template("payment.html", bus=bus, selected_seats=selected_seats, pricing=pricing)
        if not re.match(r"^[A-Za-z][A-Za-z .'-]{1,98}$", passenger_name):
            flash("Enter a valid passenger name.", "danger")
            return render_template("payment.html", bus=bus, selected_seats=selected_seats, pricing=pricing)
        if not re.match(r"^[6-9]\d{9}$", emergency_contact):
            flash("Enter a valid 10-digit emergency mobile number.", "danger")
            return render_template("payment.html", bus=bus, selected_seats=selected_seats, pricing=pricing)
        if payment_method == "UPI" and not request.form.get("upi_id", "").strip():
            flash("Enter a valid UPI ID.", "danger")
            return render_template("payment.html", bus=bus, selected_seats=selected_seats, pricing=pricing)
        if payment_method == "CARD" and (
            not request.form.get("card_holder", "").strip()
            or not request.form.get("card_number", "").strip()
            or not request.form.get("expiry", "").strip()
            or not request.form.get("cvv", "").strip()
        ):
            flash("Complete all card details before paying.", "danger")
            return render_template("payment.html", bus=bus, selected_seats=selected_seats, pricing=pricing)
        if payment_method == "WALLET" and not request.form.get("wallet_mobile", "").strip():
            flash("Enter the wallet mobile number.", "danger")
            return render_template("payment.html", bus=bus, selected_seats=selected_seats, pricing=pricing)
        if payment_outcome != "SUCCESS":
            flash("Payment failed in simulation. Please retry.", "danger")
            return render_template("payment.html", bus=bus, selected_seats=selected_seats, pricing=pricing)

        db = get_db()
        cursor = db.cursor(dictionary=True)
        try:
            db.start_transaction()
            placeholders = ",".join(["%s"] * len(selected_seats))
            cursor.execute(
                f"""
                SELECT seat_number
                FROM bus_seats
                WHERE bus_id=%s AND status='available' AND seat_number IN ({placeholders})
                FOR UPDATE
                """,
                tuple([bus_id] + selected_seats),
            )
            locked_rows = cursor.fetchall()
            if len(locked_rows) != len(selected_seats):
                db.rollback()
                flash("Seats changed during payment. Please select again.", "danger")
                return redirect(url_for("seats", bus_id=bus_id))

            cursor.execute(
                f"""
                UPDATE bus_seats
                SET status='booked'
                WHERE bus_id=%s AND seat_number IN ({placeholders})
                """,
                tuple([bus_id] + selected_seats),
            )
            cursor.execute(
                "UPDATE buses SET available_seats = available_seats - %s WHERE bus_id=%s",
                (len(selected_seats), bus_id),
            )

            booking_reference = f"GR{uuid.uuid4().hex[:8].upper()}"
            cursor.execute(
                """
                INSERT INTO bookings(
                    booking_reference, user_id, bus_id, passenger_name, emergency_contact,
                    seat_numbers, seats_booked, journey_date, total_fare, ticket_status,
                    payment_status, payment_method
                )
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,'CONFIRMED','SUCCESS',%s)
                """,
                (
                    booking_reference,
                    session["user_id"],
                    bus_id,
                    passenger_name,
                    emergency_contact or "Not Provided",
                    ",".join(selected_seats),
                    len(selected_seats),
                    journey_date,
                    pricing["total"],
                    payment_method,
                ),
            )
            booking_id = cursor.lastrowid
            cursor.execute(
                """
                INSERT INTO payments(booking_id, amount, method, provider_reference, payment_state)
                VALUES(%s,%s,%s,%s,'SUCCESS')
                """,
                (booking_id, pricing["total"], payment_method, f"PAY-{uuid.uuid4().hex[:10].upper()}"),
            )
            db.commit()
            session.pop("selected_seats", None)
            session.pop("bus_id", None)
            app.logger.info("Booking confirmed booking_id=%s user_id=%s amount=%s", booking_id, session["user_id"], pricing["total"])
            flash("Payment successful. Ticket confirmed.", "success")
            return redirect(url_for("ticket", booking_id=booking_id))
        except Error as exc:
            db.rollback()
            app.logger.exception("Booking failed for user_id=%s bus_id=%s", session["user_id"], bus_id)
            flash(f"Booking failed: {exc}", "danger")
        finally:
            cursor.close()
            db.close()

    return render_template("payment.html", bus=bus, selected_seats=selected_seats, pricing=pricing)


@app.route("/ticket/<int:booking_id>")
@login_required
def ticket(booking_id):
    booking = get_booking_or_none(booking_id, session["user_id"])
    if not booking:
        flash("Ticket not found.", "danger")
        return redirect(url_for("history"))
    add_tracking_data(booking, date_value(booking["journey_date"]))
    qr_payload = get_ticket_payload(booking)
    feedback = fetch_one("SELECT rating, comments FROM feedback WHERE booking_id=%s AND user_id=%s", (booking_id, session["user_id"]))
    return render_template("ticket.html", booking=booking, qr_payload=qr_payload, feedback=feedback)


@app.route("/download-ticket/<int:booking_id>")
@login_required
def download_ticket(booking_id):
    booking = get_booking_or_none(booking_id, session["user_id"])
    if not booking:
        flash("Ticket not found.", "danger")
        return redirect(url_for("history"))
    pdf_lines = [
        f"Booking Ref: {booking['booking_reference']}",
        f"Passenger: {booking['passenger_name']}",
        f"Bus: {booking['bus_name']} ({booking['operator_name']})",
        f"Bus Type: {booking['bus_type']}",
        f"Route: {booking['source']} to {booking['destination']}",
        f"Date: {booking['journey_date_text']}",
        f"Timing: {booking['departure_time_text']} to {booking['arrival_time_text']}",
        f"Seats: {booking['seat_numbers']}",
        f"Status: {booking['ticket_status']}",
        f"Payment: {booking['payment_status']} via {booking['payment_method']}",
        f"Amount: Rs. {booking['total_fare_text']}",
        f"Emergency Contact: {booking['emergency_contact']}",
    ]
    pdf_bytes = build_pdf_bytes(pdf_lines)
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename={booking['booking_reference']}.pdf",
            "Cache-Control": "no-store",
        },
    )


@app.route("/history")
@login_required
def history():
    bookings = fetch_all(
        """
        SELECT
            b.booking_id, b.booking_reference, b.passenger_name, b.emergency_contact, b.seat_numbers,
            b.seats_booked, b.journey_date, b.total_fare, b.ticket_status, b.payment_status,
            b.payment_method, b.booked_at,
            bu.bus_id, bu.route_code, bu.bus_name, bu.operator_name, bu.operator_type, bu.source,
            bu.destination, bu.departure_time, bu.arrival_time, bu.bus_type, bu.amenities
        FROM bookings b
        JOIN buses bu ON bu.bus_id = b.bus_id
        WHERE b.user_id=%s
        ORDER BY b.booked_at DESC
        """,
        (session["user_id"],),
    )
    for booking in bookings:
        normalize_booking(booking)

    insights = fetch_one(
        """
        SELECT
            COUNT(*) AS total_trips,
            COALESCE(SUM(total_fare), 0) AS total_spent
        FROM bookings
        WHERE user_id=%s AND ticket_status='CONFIRMED'
        """,
        (session["user_id"],),
    )
    top_destination = fetch_one(
        """
        SELECT bu.destination, COUNT(*) AS visit_count
        FROM bookings b
        JOIN buses bu ON bu.bus_id = b.bus_id
        WHERE b.user_id=%s AND b.ticket_status='CONFIRMED'
        GROUP BY bu.destination
        ORDER BY visit_count DESC, bu.destination ASC
        LIMIT 1
        """,
        (session["user_id"],),
    )
    feedback_map = {
        row["booking_id"]: row
        for row in fetch_all("SELECT booking_id, rating, comments FROM feedback WHERE user_id=%s", (session["user_id"],))
    }
    return render_template(
        "history.html",
        bookings=bookings,
        insights=insights,
        top_destination=top_destination,
        feedback_map=feedback_map,
    )


@app.route("/feedback/<int:booking_id>", methods=["POST"])
@login_required
def submit_feedback(booking_id):
    rating = positive_int(request.form.get("rating"), 0)
    comments = request.form.get("comments", "").strip()
    booking = fetch_one(
        """
        SELECT booking_id, bus_id
        FROM bookings
        WHERE booking_id=%s AND user_id=%s
        """,
        (booking_id, session["user_id"]),
    )
    if not booking:
        flash("Booking not found for feedback.", "danger")
        return redirect(url_for("history"))
    if rating < 1 or rating > 5 or not comments:
        flash("Please share a rating between 1 and 5 with a short comment.", "danger")
        return redirect(url_for("history"))
    existing = fetch_one(
        "SELECT feedback_id FROM feedback WHERE booking_id=%s AND user_id=%s",
        (booking_id, session["user_id"]),
    )
    if existing:
        execute_query(
            "UPDATE feedback SET rating=%s, comments=%s, created_at=NOW() WHERE feedback_id=%s",
            (rating, comments, existing["feedback_id"]),
        )
        flash("Feedback updated successfully.", "success")
    else:
        execute_query(
            """
            INSERT INTO feedback(booking_id, user_id, bus_id, rating, comments)
            VALUES(%s,%s,%s,%s,%s)
            """,
            (booking_id, session["user_id"], booking["bus_id"], rating, comments),
        )
        flash("Thanks for sharing your feedback.", "success")
    return redirect(url_for("history"))


@app.route("/cancel/<int:booking_id>", methods=["POST"])
@login_required
def cancel(booking_id):
    db = get_db()
    cursor = db.cursor(dictionary=True)
    try:
        db.start_transaction()
        cursor.execute(
            """
            SELECT booking_id, bus_id, seat_numbers, total_fare, ticket_status
            FROM bookings
            WHERE booking_id=%s AND user_id=%s
            FOR UPDATE
            """,
            (booking_id, session["user_id"]),
        )
        booking = cursor.fetchone()
        if not booking:
            db.rollback()
            flash("Booking not found.", "danger")
            return redirect(url_for("history"))
        if booking["ticket_status"] == "CANCELLED":
            db.rollback()
            flash("This trip is already cancelled.", "warning")
            return redirect(url_for("history"))
        seat_numbers = booking["seat_numbers"].split(",")
        placeholders = ",".join(["%s"] * len(seat_numbers))
        cursor.execute(
            f"UPDATE bus_seats SET status='available' WHERE bus_id=%s AND seat_number IN ({placeholders})",
            tuple([booking["bus_id"]] + seat_numbers),
        )
        cursor.execute(
            "UPDATE buses SET available_seats = available_seats + %s WHERE bus_id=%s",
            (len(seat_numbers), booking["bus_id"]),
        )
        refund_amount = (Decimal(booking["total_fare"]) * Decimal("0.85")).quantize(Decimal("0.01"))
        cursor.execute(
            "UPDATE bookings SET ticket_status='CANCELLED', payment_status='REFUNDED', cancelled_at=NOW() WHERE booking_id=%s",
            (booking_id,),
        )
        cursor.execute("UPDATE payments SET payment_state='REFUNDED' WHERE booking_id=%s", (booking_id,))
        db.commit()
        app.logger.info("Booking cancelled booking_id=%s user_id=%s refund=%s", booking_id, session["user_id"], refund_amount)
        flash(f"Trip cancelled. Estimated refund: Rs. {refund_amount}", "success")
    except Error as exc:
        db.rollback()
        app.logger.exception("Cancellation failed booking_id=%s user_id=%s", booking_id, session["user_id"])
        flash(f"Unable to cancel booking: {exc}", "danger")
    finally:
        cursor.close()
        db.close()
    return redirect(url_for("history"))


@app.route("/dashboard")
@login_required
def dashboard():
    totals = fetch_one(
        """
        SELECT
            COUNT(DISTINCT bu.bus_id) AS total_buses,
            COUNT(b.booking_id) AS total_bookings,
            COALESCE(SUM(CASE WHEN b.ticket_status='CONFIRMED' THEN b.total_fare ELSE 0 END), 0) AS revenue
        FROM buses bu
        LEFT JOIN bookings b ON bu.bus_id = b.bus_id
        """
    )
    popular_route = fetch_one(
        """
        SELECT CONCAT(bu.source, ' to ', bu.destination) AS route_name, COUNT(*) AS bookings_count
        FROM bookings b
        JOIN buses bu ON bu.bus_id = b.bus_id
        WHERE b.ticket_status='CONFIRMED'
        GROUP BY bu.source, bu.destination
        ORDER BY bookings_count DESC
        LIMIT 1
        """
    )
    top_bus = fetch_one(
        """
        SELECT bu.bus_name, COUNT(*) AS trips
        FROM bookings b
        JOIN buses bu ON bu.bus_id = b.bus_id
        WHERE b.ticket_status='CONFIRMED'
        GROUP BY bu.bus_name
        ORDER BY trips DESC
        LIMIT 1
        """
    )
    chart_data = fetch_all(
        """
        SELECT DATE_FORMAT(booked_at, '%%b %%d') AS booking_day, COALESCE(SUM(total_fare), 0) AS day_revenue
        FROM bookings
        WHERE booked_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
        GROUP BY DATE(booked_at), DATE_FORMAT(booked_at, '%%b %%d')
        ORDER BY DATE(booked_at)
        """
    )
    feedback_stats = fetch_one(
        """
        SELECT COALESCE(AVG(rating), 0) AS average_rating, COUNT(*) AS total_reviews
        FROM feedback
        """
    )
    for item in chart_data:
        item["bar_height"] = max(float(item["day_revenue"]) / 20, 8)
    return render_template(
        "dashboard.html",
        totals=totals,
        popular_route=popular_route,
        top_bus=top_bus,
        chart_data=chart_data,
        feedback_stats=feedback_stats,
    )


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("home"))


try:
    ensure_schema()
except Error as exc:
    STARTUP_ERROR = str(exc)


if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "0") == "1")
