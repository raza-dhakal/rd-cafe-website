CREATE DATABASE IF NOT EXISTS rd_cafe_db;
-- Database select garne
USE rd_cafe_db;
-- Menu table banaune
CREATE TABLE IF NOT EXISTS menu (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    price DECIMAL(10, 2) NOT NULL,
    image_url VARCHAR(255) NOT NULL,
    category VARCHAR(50) DEFAULT 'Coffee'
);
-- Sample data insert garne (yo sample ho, a-afno menu halna sakinchha)
INSERT INTO menu (name, description, price, image_url) VALUES
('Espresso', 'A concentrated coffee brewed by forcing a small amount of nearly boiling water through finely-ground coffee beans.', 150.00, 'espresso.jpg'),
('Latte', 'A coffee drink made with espresso and steamed milk, with a layer of foam on top.', 220.00, 'latte.jpg'),
('Cappuccino', 'An espresso-based coffee drink that originated in Italy, prepared with steamed milk foam.', 200.00, 'cappuccino.jpg'),
('Americano', 'A type of coffee drink prepared by diluting an espresso with hot water.', 180.00, 'americano.jpg');

-- Purano sabai data hataune, taki naya categorized data halna sajilo hos
-- Database select garne
USE rd_cafe_db;

-- Purano data lai completely hataune
TRUNCATE TABLE menu;

-- Naya, clean data feri insert garne
INSERT INTO menu (name, description, price, image_url, category) VALUES
('Espresso', 'Concentrated coffee for the true connoisseur.', 150.00, 'hot-espresso.jpg', 'Hot Coffee'),
('Cappuccino', 'A perfect balance of espresso, steamed milk, and foam.', 200.00, 'hot-cappuccino.jpg', 'Hot Coffee'),
('RD Special Latte', 'Our signature latte with a hint of Nepali spices.', 250.00, 'hot-latte.jpg', 'Hot Coffee'),
('Iced Americano', 'Crisp, bold espresso shots topped with cold water and ice.', 180.00, 'iced-americano.jpg', 'Iced Coffee'),
('Iced Mocha', 'A chilly delight of espresso, chocolate, and milk.', 260.00, 'iced-mocha.jpg', 'Iced Coffee'),
('Cold Brew', 'Steeped for 12 hours for a smooth, low-acid flavor.', 280.00, 'cold-brew.jpg', 'Iced Coffee'),
('Lava Cake', 'Molten chocolate cake with a gooey center. A true indulgence!', 350.00, 'lava-cake.jpg', 'Cake'),
('Cheesecake', 'Creamy, rich, and delicious New York style cheesecake.', 320.00, 'cheesecake.jpg', 'Cake'),
('RD House Red', 'A smooth, full-bodied red wine, perfect for relaxing evenings.', 700.00, 'red-wine.jpg', 'Wine'),
('Crisp White Wine', 'A light and refreshing white wine with fruity notes.', 700.00, 'white-wine.jpg', 'Wine'),
('Fresh Orange Juice', '100% freshly squeezed orange juice to brighten your day.', 200.00, 'orange-juice.jpg', 'Juice');

-- Database select garne
USE rd_cafe_db;

-- Step 2: 'users' table banaune (yedi pahilai baneko chhaina bhane)
-- Yo table le user ko account details store garchha
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

USE rd_cafe_db;

-- 1. Admin table
CREATE TABLE IF NOT EXISTS admin (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    secret_key_hash VARCHAR(255) NOT NULL
);

-- 2. OTP logs table
CREATE TABLE IF NOT EXISTS otp_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    admin_email VARCHAR(100) NOT NULL,
    otp_code VARCHAR(10) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_used BOOLEAN DEFAULT FALSE
);

INSERT INTO admin (email, password_hash, secret_key_hash) 
VALUES ('rjndkl1224@gmail.com',
 '$2b$12$qU/5IxSGm9PJJu5ZaCXc.OLu7V5rRMy4pLSIGkcOeSmt2Ng21Zhee', 
 '$2b$12$UG2elhs8kWWKu/UyFyKvGetyZ7FBnVLYrWW1.WvJD6amEO0wGzgC.'
 )
ON DUPLICATE KEY UPDATE 
    password_hash = VALUES(password_hash),
    secret_key_hash = VALUES(secret_key_hash); -- Yedi pahilai email chha bhane error nadikhaos
    
    -- Using your database
USE rd_cafe_db;

-- Updating the admin record with your new, final hashes
UPDATE admin
SET 
    -- Your FINAL Password Hash for 'RazanIsAdmin'
    password_hash = '$2b$12$GsWZEYypm6ZQv0u./U4fJeFyWFCkyrK/tbO8CaQReTdgQ8Keyv1Nu',
    
    -- Your FINAL Secret Key Hash for 'RD_Cafe_2024'
    secret_key_hash = '$2b$12$YaMQQDGeTqJ3F/nhOiX0W..leM1rwwGclDqgCpCcs7CpX3kOMLymm'
WHERE 
    -- Updating the record for this specific email
    email = 'rjndkl1224@gmail.com';

-- This line is just to confirm the update
SELECT * FROM admin WHERE email = 'rjndkl1224@gmail.com';
SELECT password_hash, secret_key_hash 
FROM rd_cafe_db.admin 
WHERE email = 'rjndkl1224@gmail.com';

DELETE FROM rd_cafe_db.admin WHERE email = 'rjndkl1224@gmail.com';

INSERT INTO rd_cafe_db.admin (email, password_hash, secret_key_hash) 
VALUES (
    'rjndkl1224@gmail.com',
    '$2b$12$GsWZEYypm6ZQv0u./U4fJeFyWFCkyrK/tbO8CaQReTdgQ8Keyv1Nu', 
    '$2b$12$YaMQQDGeTqJ3F/nhOiX0W..leM1rwwGclDqgCpCcs7CpX3kOMLymm'
);
SELECT * FROM rd_cafe_db.admin;

USE rd_cafe_db; -- Make sure you are using the correct database

USE rd_cafe_db; -- Make sure the correct database is selected

-- Drop the table if it exists with errors, to start fresh
DROP TABLE IF EXISTS orders;

-- Create the table with the corrected foreign key constraint
CREATE TABLE orders (
    order_id INT AUTO_INCREMENT PRIMARY KEY,
    customer_name VARCHAR(255) NOT NULL,
    menu_item_id INT NOT NULL,
    quantity INT NOT NULL,
    payment_method VARCHAR(50) NOT NULL,
    order_status VARCHAR(50) DEFAULT 'Pending',
    order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- This column can be NULL if the order is from a guest (not logged in)
    user_id INT NULL, 
    
    -- Define the constraints at the end for clarity
    CONSTRAINT fk_menu_item
        FOREIGN KEY (menu_item_id) 
        REFERENCES menu(id)
        ON DELETE RESTRICT, -- Prevent deleting a menu item if it has orders

    CONSTRAINT fk_user
        FOREIGN KEY (user_id) 
        REFERENCES users(id)
        ON DELETE SET NULL -- If a user is deleted, keep the order but set user_id to NULL
);