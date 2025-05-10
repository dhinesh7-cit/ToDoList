create database todo_db1;
use todo_db1;
CREATE TABLE to_do_data (
    task_id INT AUTO_INCREMENT PRIMARY KEY,
    task VARCHAR(255) NOT NULL,
    date DATE NOT NULL,
    time TIME NOT NULL,
    priority_id INT NOT NULL,
    category_id INT NOT NULL,
    user_id INT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);
CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL
);
CREATE TABLE task_priority (
    priority_id INT AUTO_INCREMENT PRIMARY KEY,
    priority_level VARCHAR(50) NOT NULL
);

-- Insert some sample priority levels
INSERT INTO task_priority (priority_level) VALUES ('Low'), ('Medium'), ('High');

CREATE TABLE task_categories (
    category_id INT AUTO_INCREMENT PRIMARY KEY,
    category_name VARCHAR(50) NOT NULL
);

-- Insert some sample categories
INSERT INTO task_categories (category_name) 
VALUES ('Work'), ('Personal'), ('Urgent'), ('General');
use todo_db1;
ALTER TABLE users ADD email VARCHAR(255) NOT NULL;

INSERT INTO to_do_data (task, date, time, priority_id, category_id, user_id)
VALUES 
('Complete Presentation', DATE_SUB(CURDATE(), INTERVAL 1 DAY), '14:30:00', 
(SELECT priority_id FROM task_priority WHERE priority_level = 'Medium'), 
(SELECT category_id FROM task_categories WHERE category_name = 'Work'),
(SELECT user_id FROM users WHERE username = 'dhinesh7')),

('Grocery Shopping', DATE_SUB(CURDATE(), INTERVAL 1 DAY), '17:00:00', 
(SELECT priority_id FROM task_priority WHERE priority_level = 'Low'), 
(SELECT category_id FROM task_categories WHERE category_name = 'Personal'),
(SELECT user_id FROM users WHERE username = 'dhinesh7')),

('Call with Client', DATE_SUB(CURDATE(), INTERVAL 1 DAY), '10:00:00', 
(SELECT priority_id FROM task_priority WHERE priority_level = 'High'), 
(SELECT category_id FROM task_categories WHERE category_name = 'Urgent'),
(SELECT user_id FROM users WHERE username = 'dhinesh7'));
