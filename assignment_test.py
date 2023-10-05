#!/usr/bin/env python
# coding: utf-8

# In[1]:


import re
from urllib.parse import unquote


# In[2]:


# Simple user database for this assignment
database = {}


# In[3]:


def sanitize_input(input_str):
    # Implement basic input sanitization to protect against SQL injection
    sanitized_str = re.sub(r"[;'\"-]", "", input_str)
    return sanitized_str


# In[4]:


def prevent_sql_injection(input_query):
    sanitized_query = sanitize_input(input_query)
    # Perform the SQL query using the sanitized input
    result = database.get(sanitized_query, "No result")
    return result


# In[5]:


def prevent_xss(input_text):
    # Implement basic HTML escaping to protect against XSS attacks
    escaped_text = input_text.replace("<", "&lt;").replace(">", "&gt;")
    return escaped_text


# In[6]:


# Function to register a new user
def register_user():
    username = input("Enter a new username: ")
    if username in database:
        print("Username already exists. Please choose another one.")
        return

    password = input("Enter a password: ")
    email = input("Enter email address: ")
    # Store user information in the database
    database[username] = {
        "password": password,
        "email": email
    }
    print("Registration successful!")
    while True:
        cont = input("Do you want to register another user? (yes/no): ")
        if cont.lower() != "yes":
            break
   
            
        
    


# In[7]:


# Function to login
def login_user():
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    # Prevent SQL Injection
    sanitized_username = sanitize_input(username)
    sanitized_password = sanitize_input(password)

    if database.get(sanitized_username) == sanitized_password:
        print("Login successful")
    else:
        print("Login failed")


# In[8]:


# Function to Browse online catalog
def search_query():
    search_query = input("Enter your online product query: ")

    # Prevent SQL Injection
    result = prevent_sql_injection(search_query)
    print("Search result:", result)

    # Prevent XSS
    sanitized_result = prevent_xss(result)
    print("Sanitized result:", sanitized_result)


# In[9]:


# Main program
while True:
    print("\nWelcome to the online shopping System")
    print("1. Register")
    print("2. Login")
    print("3. Browse product catalog")
    print("4. Exit")

    choice = input("Enter your choice: ")

    if choice == "1":
        register_user()
    elif choice == "2":
        login_user()
    elif choice == "3":
        search_query()
    elif choice == "4":
        print("Goodbye!")
        break
    else:
        print("Invalid choice. Please choose again.")


# In[10]:


class WebApplicationFirewall:
    def __init__(self):
        self.sql_injection_patterns = ["SELECT", "INSERT", "UPDATE", "DELETE", "UNION", "1=1"]
        self.xss_patterns = ["<script>","javascript:", "alert(", "onerror="]

    def detect_sql_injection(self, input_data):
        for pattern in self.sql_injection_patterns:
            if pattern.lower() in input_data.lower():
                return True
        return False

    def detect_xss(self, input_data):
        for pattern in self.xss_patterns:
            if pattern.lower() in input_data.lower():
                return True
        return False

    def protect(self, input_data):
        if self.detect_sql_injection(input_data):
            return "SQL Injection Detected! Request Blocked."
        elif self.detect_xss(input_data):
            return "XSS Attack Detected! Request Blocked."
        else:
            return "Request Passed WAF Security Check. Welcome to the online shopping system"


# In[11]:


# Test data sample:
if __name__ == "__main__":
    waf = WebApplicationFirewall()

    # Simulated user input
    user_input_sql_injection = "SELECT * FROM users"
    user_input_xss = "<script>alert('XSS')</script>"
    safe_user_input = "Hello, World!"

    result_sql_injection = waf.protect(user_input_sql_injection)
    result_xss = waf.protect(user_input_xss)
    result_safe = waf.protect(safe_user_input)

    print(result_sql_injection)  # Output: SQL Injection Detected! Request Blocked.
    print(result_xss)  # Output: XSS Attack Detected! Request Blocked.
    print(result_safe)  # Output: Request Passed WAF Security Check.Welcome to the online shopping system


# In[ ]:




