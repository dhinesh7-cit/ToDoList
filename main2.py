import re
import mysql.connector
import customtkinter as ctk
from tkinter import messagebox
from fpdf import FPDF
import matplotlib.pyplot as plt
from datetime import datetime
from tkinter import filedialog
import bcrypt

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# Connect to MySQL Database
cnt = mysql.connector.connect(
    host="localhost",  # Update with your host
    user="root",       # Update with your username
    password="@dhinesh6348088",  # Update with your password
    database="todo_db1"  # Use your database name
)
cursor = cnt.cursor()

# Hash password for security
def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)

# Verify hashed password
def check_password(password, hashed_password):
    # Ensure hashed_password is bytes
    if isinstance(hashed_password, str):
        hashed_password = hashed_password.encode()
    return bcrypt.checkpw(password.encode(), hashed_password)


# Global variable for the logged-in user
current_user_id = None
current_username = None

# Signup Function
# Signup Function
def signup():
    def register_user():
        username = username_entry.get()
        email = email_entry.get()
        password = password_entry.get()
        reentered_password = reentered_password_entry.get()

        # Check if email is in valid format
        email_pattern = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
        if not re.match(email_pattern, email):
            messagebox.showerror("Error", "Please enter a valid email address.")
            return

        # Check if passwords match
        if password != reentered_password:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        hashed_password = hash_password(password)

        try:
            cursor.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)", (username, email, hashed_password))
            cnt.commit()
            messagebox.showinfo("Success", "Signup successful! You can now login.")
            signup_window.destroy()  # Close the signup window
            login()  # Open the login window after successful signup
        except mysql.connector.errors.IntegrityError:
            messagebox.showerror("Error", "Username already exists!")

    signup_window = ctk.CTkToplevel()
    signup_window.title("Signup")
    signup_window.geometry("400x400")

    ctk.CTkLabel(signup_window, text="Username").pack(pady=5)
    username_entry = ctk.CTkEntry(signup_window, width=200)
    username_entry.pack(pady=5)

    ctk.CTkLabel(signup_window, text="Email").pack(pady=5)
    email_entry = ctk.CTkEntry(signup_window, width=200)
    email_entry.pack(pady=5)

    ctk.CTkLabel(signup_window, text="Password").pack(pady=5)
    password_entry = ctk.CTkEntry(signup_window, show="*", width=200)
    password_entry.pack(pady=5)

    ctk.CTkLabel(signup_window, text="Re-Enter Password").pack(pady=5)
    reentered_password_entry = ctk.CTkEntry(signup_window, show="*", width=200)
    reentered_password_entry.pack(pady=5)

    ctk.CTkButton(signup_window, text="Register", command=register_user).pack(pady=20)

# Login Function
def login():
    global current_user_id, current_username

    def authenticate_user():
        global current_user_id, current_username
        username = username_entry.get()
        password = password_entry.get()

        cursor.execute("SELECT user_id, password FROM users WHERE username = %s", (username,))
        result = cursor.fetchone()

        if result and check_password(password, result[1]):
            current_user_id = result[0]
            current_username = username
            messagebox.showinfo("Success", "Login successful!")
            login_window.destroy()
            show_main_window()
        else:
            messagebox.showerror("Error", "Invalid username or password")

    login_window = ctk.CTk()
    login_window.title("Login")
    login_window.geometry("400x300")

    ctk.CTkLabel(login_window, text="Username").pack(pady=5)
    username_entry = ctk.CTkEntry(login_window, width=200)
    username_entry.pack(pady=5)

    ctk.CTkLabel(login_window, text="Password").pack(pady=5)
    password_entry = ctk.CTkEntry(login_window, show="*", width=200)
    password_entry.pack(pady=5)

    ctk.CTkButton(login_window, text="Login", command=authenticate_user).pack(pady=20)
    ctk.CTkButton(login_window, text="Signup", command=lambda: [login_window.destroy(), signup()]).pack(pady=5)

    login_window.mainloop()


# Load tasks for the logged-in user
# Load tasks for the logged-in user
# Load tasks for the logged-in user
def load_existing_tasks():
    global current_user_id

    # Fetch tasks along with priority and category information
    # Load tasks for the logged-in user
def load_existing_tasks():
    global current_user_id

    # Fetch tasks along with priority and category information
    cursor.execute(cursor.execute("""
    SELECT DISTINCT t.task, t.date, t.time, p.priority_level, c.category_name
    FROM to_do_data t
    JOIN task_priority p ON t.priority_id = p.priority_id
    JOIN task_categories c ON t.category_id = c.category_id
    WHERE t.user_id = %s
    ORDER BY 
        CASE 
            WHEN p.priority_level = 'High' THEN 1
            WHEN p.priority_level = 'Medium' THEN 2
            WHEN p.priority_level = 'Low' THEN 3
            ELSE 4
        END, 
        t.date, t.time; """, (current_user_id,)), (current_user_id,))
    
    tasks = cursor.fetchall()

    task_textbox.delete("1.0", "end")

    # Insert sorted tasks without the box structure
    for task in tasks:
        task_textbox.insert("end", f"Task: {task[0]}\n")
        task_textbox.insert("end", f"Date & Time: {task[1]} {task[2]}\n")
        task_textbox.insert("end", f"Priority: {task[3]}\n")
        task_textbox.insert("end", f"Category: {task[4]}\n")
        task_textbox.insert("end", "-"*50 + "\n")  # Line break between tasks




# Add task for the logged-in user
def add_task():
    global current_user_id

    task = task_entry.get()
    priority = priority_var.get()
    category = category_var.get()

    if task and priority and category:
        cursor.execute("SELECT priority_id FROM task_priority WHERE priority_level = %s", (priority,))
        priority_id = cursor.fetchone()[0]

        cursor.execute("SELECT category_id FROM task_categories WHERE category_name = %s", (category,))
        category_id = cursor.fetchone()[0]

        date_time = datetime.now()
        date_str = date_time.strftime("%Y-%m-%d")
        time_str = date_time.strftime("%H:%M")

        cursor.execute(
            "INSERT INTO to_do_data (task, date, time, priority_id, category_id, user_id) VALUES (%s, %s, %s, %s, %s, %s)",
            (task, date_str, time_str, priority_id, category_id, current_user_id)
        )
        cnt.commit()

        load_existing_tasks()
        task_entry.delete(0, 'end')
        messagebox.showinfo("Success", "Task added successfully!")
    else:
        messagebox.showerror("Error", "Please fill in all fields.")
# Global variable to store logged in user ID
logged_in_user_id = None

# Function to authenticate user during login
def authenticate_user():
    global logged_in_user_id  # Use the global variable to access it outside the function

    username = username_entry.get()
    password = password_entry.get()

    # Query to fetch the user details
    cursor.execute("SELECT user_id, username, password FROM users WHERE username = %s", (username,))
    result = cursor.fetchone()

    if result and check_password(password, result[2]):  # Assuming password is the 3rd column
        logged_in_user_id = result[0]  # Store the user ID here
        messagebox.showinfo("Login Successful", "Welcome!")
        login_window.destroy()
        load_existing_tasks()
    else:
        messagebox.showerror("Login Failed", "Invalid username or password")

# Generate PDF
from fpdf import FPDF

# Button to generate PDF
# Button to generate PDF
def generate_pdf():
    # Ask where to save the PDF
    file_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF Files", "*.pdf")])
    
    if file_path:
        # Modify the query to fetch tasks only for the logged-in user
        cursor.execute("SELECT task, date, time, priority_id, category_id FROM to_do_data WHERE user_id = %s", (current_user_id,))
        tasks = cursor.fetchall()
        
        # Create PDF
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)

        # Add Title
        pdf.cell(200, 10, txt="To-Do List", ln=True, align="C")

        # Set column widths
        col_widths = [60, 50, 40, 40]

        # Add table headers
        pdf.ln(10)  # Line break
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(col_widths[0], 10, "Task", border=1, align="C")
        pdf.cell(col_widths[1], 10, "Date and Time", border=1, align="C")
        pdf.cell(col_widths[2], 10, "Priority Level", border=1, align="C")
        pdf.cell(col_widths[3], 10, "Task Category", border=1, align="C")
        pdf.ln()

        # Add task data rows
        pdf.set_font("Arial", size=10)
        for task in tasks:
            cursor.execute("SELECT priority_level FROM task_priority WHERE priority_id = %s", (task[3],))
            priority_level = cursor.fetchone()[0]
            
            cursor.execute("SELECT category_name FROM task_categories WHERE category_id = %s", (task[4],))
            category_name = cursor.fetchone()[0]
            
            pdf.cell(col_widths[0], 10, task[0], border=1, align="C")
            pdf.cell(col_widths[1], 10, f"{task[1]} {task[2]}", border=1, align="C")
            pdf.cell(col_widths[2], 10, priority_level, border=1, align="C")
            pdf.cell(col_widths[3], 10, category_name, border=1, align="C")
            pdf.ln()

        pdf.output(file_path)  # Save PDF to the chosen file path
        messagebox.showinfo("Success", f"PDF generated successfully and saved to {file_path}")



# Generate Graph
def generate_graph():
    global current_user_id

    # Query to get tasks grouped by date
    cursor.execute("""
        SELECT date, COUNT(*) 
        FROM to_do_data 
        WHERE user_id = %s 
        GROUP BY date 
        ORDER BY date;
    """, (current_user_id,))
    data = cursor.fetchall()

    # Extract dates and counts for a single line plot
    dates = [x[0].strftime("%Y-%m-%d") for x in data]  # Convert date to string for better plotting
    counts = [x[1] for x in data]

    # Plot data
    plt.figure(figsize=(10, 6))
    plt.plot(dates, counts, marker="o", label="Tasks per Day", color="blue")

    # Adding labels and title
    plt.title("Tasks Per Day", fontsize=14)
    plt.xlabel("Date", fontsize=12)
    plt.ylabel("Number of Tasks", fontsize=12)
    plt.xticks(rotation=45)
    plt.grid(visible=True, linestyle='--', alpha=0.6)

    # Add legend
    plt.legend()

    # Show the graph
    plt.tight_layout()  # Adjust layout to prevent cutoff
    plt.show()


# Main To-Do Window
def show_main_window():
    global current_username

    main_window = ctk.CTk()
    main_window.title("To-Do List")
    main_window.geometry("700x700")

    ctk.CTkLabel(main_window, text=f"Welcome, {current_username}", font=("Arial", 20, "bold")).pack(pady=10)
    
    global task_textbox, task_entry, priority_var, category_var

    task_textbox = ctk.CTkTextbox(main_window, width=700, height=200)
    task_textbox.pack(pady=10)

    task_entry = ctk.CTkEntry(main_window, placeholder_text="Enter Task", width=350)
    task_entry.pack(pady=5)

    priority_var = ctk.StringVar(value="Low")
    ctk.CTkOptionMenu(main_window, variable=priority_var, values=["Low", "Medium", "High"]).pack(pady=5)

    category_var = ctk.StringVar(value="Work")
    ctk.CTkOptionMenu(main_window, variable=category_var, values=["Work", "Personal", "Urgent"]).pack(pady=5)

    ctk.CTkButton(main_window, text="Add Task", command=add_task).pack(pady=5)
    ctk.CTkButton(main_window, text="Generate PDF", command=generate_pdf).pack(pady=5)
    ctk.CTkButton(main_window, text="Generate Graph", command=generate_graph).pack(pady=5)

    load_existing_tasks()
    main_window.mainloop()

# Start by showing the login window
login()
