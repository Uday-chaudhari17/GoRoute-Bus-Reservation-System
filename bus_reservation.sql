CREATE DATABASE IF NOT EXISTS bus_reservation;
USE bus_reservation;

CREATE TABLE IF NOT EXISTS users (
    user_id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

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
);

CREATE TABLE IF NOT EXISTS bus_seats (
    seat_id INT PRIMARY KEY AUTO_INCREMENT,
    bus_id INT NOT NULL,
    seat_number VARCHAR(10) NOT NULL,
    status ENUM('available', 'booked') DEFAULT 'available',
    UNIQUE KEY uniq_bus_seat (bus_id, seat_number),
    FOREIGN KEY (bus_id) REFERENCES buses(bus_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS bus_stops (
    stop_id INT PRIMARY KEY AUTO_INCREMENT,
    bus_id INT NOT NULL,
    stop_name VARCHAR(100) NOT NULL,
    stop_order INT NOT NULL,
    arrival_offset_mins INT NOT NULL DEFAULT 0,
    departure_offset_mins INT NOT NULL DEFAULT 0,
    UNIQUE KEY uniq_bus_stop (bus_id, stop_order),
    FOREIGN KEY (bus_id) REFERENCES buses(bus_id) ON DELETE CASCADE
);

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
);

CREATE TABLE IF NOT EXISTS payments (
    payment_id INT PRIMARY KEY AUTO_INCREMENT,
    booking_id INT NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    method VARCHAR(20) NOT NULL,
    provider_reference VARCHAR(40) NOT NULL,
    payment_state ENUM('SUCCESS', 'FAILED', 'REFUNDED') DEFAULT 'SUCCESS',
    paid_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (booking_id) REFERENCES bookings(booking_id) ON DELETE CASCADE
);

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
);

INSERT INTO buses (
    route_code, bus_name, operator_name, operator_type, source, destination, total_seats,
    available_seats, fare, departure_time, arrival_time, bus_type, rating, amenities
)
SELECT * FROM (
    SELECT 'GR101', 'GoRoute Express', 'GoRoute', 'Private', 'Pune', 'Mumbai', 40, 40, 799.00, '06:30:00', '10:15:00', 'AC Seater', 4.6, 'WiFi, Charging Point, Water Bottle'
    UNION ALL
    SELECT 'GR102', 'Night Rider', 'GoRoute', 'Private', 'Bangalore', 'Chennai', 36, 36, 1099.00, '21:00:00', '05:45:00', 'AC Sleeper', 4.8, 'Blanket, Charging Point, Live Tracking'
    UNION ALL
    SELECT 'GR103', 'Royal Cruiser', 'InterState', 'Private', 'Delhi', 'Jaipur', 40, 40, 699.00, '07:15:00', '12:00:00', 'Sleeper', 4.3, 'Air Suspension, Water Bottle'
    UNION ALL
    SELECT 'GR104', 'Metro Link', 'GoRoute', 'Private', 'Hyderabad', 'Vijayawada', 32, 32, 649.00, '09:30:00', '15:00:00', 'AC Seater', 4.4, 'Live Tracking, Charging Point'
    UNION ALL
    SELECT 'GR105', 'Sunrise Travels', 'Sunrise', 'Private', 'Chennai', 'Coimbatore', 36, 36, 949.00, '23:00:00', '06:30:00', 'AC Sleeper', 4.7, 'Blanket, Snacks'
    UNION ALL
    SELECT 'GS201', 'Maharashtra State Connect', 'MSRTC', 'Private', 'Pune', 'Nashik', 40, 40, 499.00, '08:00:00', '12:00:00', 'Non AC Seater', 4.2, 'Budget Fare'
    UNION ALL
    SELECT 'GS202', 'Maharashtra Highway', 'MSRTC', 'Private', 'Nashik', 'Mumbai', 40, 40, 399.00, '13:15:00', '17:45:00', 'Non AC Seater', 4.1, 'Budget Fare'
    UNION ALL
    SELECT 'GS203', 'State Flyer', 'APSRTC', 'Private', 'Hyderabad', 'Warangal', 36, 36, 349.00, '07:30:00', '10:45:00', 'Non AC Seater', 4.0, 'Live ETA'
    UNION ALL
    SELECT 'GS204', 'Green Line', 'KSRTC', 'Private', 'Bangalore', 'Mysore', 36, 36, 299.00, '06:45:00', '09:45:00', 'Non AC Seater', 4.3, 'Frequent Timetable'
) AS seed_data
WHERE NOT EXISTS (SELECT 1 FROM buses);
