# CAPSTONE-Password-Manager
**Enterprise password manager for CIST 1451 CAPTSTONE class**

This is a password manager that implements user roles and audit logging alongside typical password manager functionality.

## Features

- **Secure Password Storage:** Store and manage passwords securely using encryption.
- **User Authentication:** Ensure only authorized users can access the system.
- **Cross-Platform Support:** Accessible via web browsers and a mobile app (not included in this repo).
- **Customizable Interface:** Ability to customize and change the UI as needed.

## Technologies Used

The project is built using the following technologies:

- **Python and Flask**: Backend logic and application functionality.
- **HTML**: Structuring the web interface.
- **JavaScript**: Enhancing interactivity on the front-end.
- **T-SQL**: Database management and query execution.
- **CSS and Bootstrap**: Styling the web pages.

## Setup and Installation

### To run the CAPSTONE Password Manager locally, follow these steps:

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/slkirby22/CAPSTONE-Password-Manager.git
   cd CAPSTONE-Password-Manager

2. **Create and Activate a Virtual Environment:**
    ```bash
    python -m venv venv
    ./venv/Scripts/activate

3. **Install Dependencies:**
Ensure you have Python installed. Then, install the required Python packages:
    ```bash
    pip install -r requirements.txt

4. **Configure the Database:**
Set up the database using the provided SQL scripts or configuration files.

5. **Run the Application:**
Start the application locally:
    ```bash
    python app.py

6. **Access the Application:**
Open your web browser and navigate to:
http://localhost:5000


### To run the Password Manager in production, it recommended that...
1. You use a production WSGI server instead of the built-in Flask development server.
2. You change database user password and username.
3. You delete the default admin user after initialization or change it's username and password.
4. You use HTTPS and edit configuration variables accordingly.
5. Store sensitive information, such as secret keys and database credentials, in environment variables instead of hardcoding them.
6. Monitor the application for unusual activity or performance issues.
7. Limit access to necessary files, directories, and database permissions to minimize security risks.
8. Schedule regular backups of your database and application files to prevent data loss.
9. Protect the server by configuring a firewall and applying security rules to restrict unwanted traffic.
10. Regularly update your Python packages and dependencies to patch security vulnerabilities.
## Development

Run the test suite with:
```bash
pytest
```

Example output:
```
3 passed in 0.59s
```



## Contact
For questions or feedback, please contact the repository owner @slkirby22.