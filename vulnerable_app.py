# Task 3: Secure Coding Review - Vulnerable Implementation
from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

@app.route('/user_profile')
def user_profile():
    # Fetching the user input directly from URL parameters
    user_id = request.args.get('id')
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # VULNERABILITY 1: SQL Injection (SQLi)
    # The user input is concatenated directly into the query string using an f-string.
    query = f"SELECT username, email, bio FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    user_data = cursor.fetchone()
    conn.close()
    
    if user_data:
        # VULNERABILITY 2: Reflective Cross-Site Scripting (XSS)
        # Using render_template_string with raw variables bypasses Jinja2's auto-escaping.
        html_response = f"""
        <h1>User Profile Dashboard</h1>
        <p>Welcome, {user_data[0]}!</p>
        <p>Email: {user_data[1]}</p>
        <p>Bio: {user_data[2]}</p>
        """
        return render_template_string(html_response)
        
    return "User profile not found", 404

if __name__ == "__main__":
    print("[*] Running vulnerable application on http://127.0.0.1:5000")
    app.run(debug=True)
    