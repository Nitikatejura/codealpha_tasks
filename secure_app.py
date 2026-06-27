# Task 3: Secure Coding Review - Patched Secure Implementation
from flask import Flask, request, render_template
import sqlite3
import html

app = Flask(__name__)

@app.route('/user_profile')
def user_profile():
    user_id = request.args.get('id')
    
    # Input Validation: Ensure an ID is actually provided
    if not user_id:
        return "Bad Request: Missing profile identifier", 400

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # REMEDIATION 1: Parameterized Query / Prepared Statements
    # Using the '?' placeholder forces the database engine to treat user input 
    # strictly as data, completely neutralizing SQL Injection (SQLi).
    query = "SELECT username, email, bio FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    user_data = cursor.fetchone()
    conn.close()
    
    if user_data:
        # REMEDIATION 2: Contextual Output Encoding / Template Rendering
        # Instead of raw string interpolation, we pass variables to an external template
        # or sanitize explicitly. Jinja2 automatically escapes HTML entities to prevent XSS.
        safe_username = html.escape(user_data[0])
        safe_email = html.escape(user_data[1])
        safe_bio = html.escape(user_data[2])
        
        # In a real app, render_template('profile.html', ...) is ideal. 
        # Here we simulate safe rendering using explicit HTML escaping.
        html_response = f"""
        <h1>User Profile Dashboard (Secured)</h1>
        <p>Welcome, {safe_username}!</p>
        <p>Email: {safe_email}</p>
        <p>Bio: {safe_bio}</p>
        """
        return html_response
        
    return "User profile not found", 404

if __name__ == "__main__":
    print("[*] Running secured application on http://127.0.0.1:5001")
    app.run(debug=True, port=5001)