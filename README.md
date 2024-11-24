# 🌟 AladdinX - Email Header Analyzer 🧑‍💻🔍

AladdinX is an open-source tool designed to secure both personal and organizational email communication. With a range of features like **AI-driven analysis**, **suspicious keyword detection**, and **individual parameter analysis** (including SPF, DKIM, DMARC, etc.) with detailed interpretations, **IP reputation and geolocation analysis**, **attachment analysis with sandboxing** for links, **email header parsing**, and much more, AladdinX simplifies email security. 

This versatile tool is designed to be user-friendly, making it suitable for both **tech-savvy professionals** and **non-technical users** alike, ensuring comprehensive email security for everyone. 💡🔒


---
# AladdinX Demo

Check out the demo video of **AladdinX**:

https://github.com/user-attachments/assets/680752ff-394d-4965-9dad-ee832be04805

---

## 🚀 Features

- **🔒 Secure Email Analysis**: No external databases are used, ensuring complete privacy.
- **🛡️ Threat Detection**: Integrates with VirusTotal and IPGeolocation for enhanced security.
- **📤 Email Header Parsing**: Parse and analyze email headers for suspicious activity.
- **📂 Sandboxed Attachments**: Safely handle attachments in a sandbox environment.
- **🔌 Easy Integration**: Easily integrate with other tools and services like VirusTotal and IPGeolocation.

---

## 🛠️ Installation

Follow these steps to set up AladdinX on your machine:

### Prerequisites:
1. Install Python 3.8 or above.
2. Install **Django** and **other dependencies** listed in `requirements.txt`.

### Steps:
1. **Clone the repository**:
    ```bash
    git clone https://github.com/Muhammad-Shaheer-khan/AladdinX.git
    ```
2. **Navigate to the project folder**:
    ```bash
    cd AladdinX
    ```

3. **Set up a virtual environment**:
    - On Windows:
        ```bash
        python -m venv venv
        ```
    - On Mac/Linux:
        ```bash
        python3 -m venv venv
        ```

4. **Activate the virtual environment**:
    - On Windows:
        ```bash
        .\venv\Scripts\activate
        ```
    - On Mac/Linux:
        ```bash
        source venv/bin/activate
        ```

5. **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

6. **Set up API keys**:
    - Register and get API keys for:
      - [VirusTotal](https://www.virustotal.com/gui)
      - [IPGeolocation](https://ipgeolocation.io/)
      - [Gemini](https://ai.google.dev/gemini-api/docs/api-key)
    And just move to the email_analysis folder in the view.py file and paste inside the function named as "api".

7. **Run the server**:
    ```bash
    python manage.py runserver
    ```

8. **Access the app**: Open your browser and navigate to `http://127.0.0.1:8000/` to use AladdinX locally.

---

## ⚙️ Usage

### How to analyze an email header:

1. **Get the Email Header**:  
   - Currently, only **Gmail** headers are supported.  
   - Extract the header from Gmail by following these steps:
     - Open the email and click on the three dots (More options).
     - Select **Show original**.
     - Copy the entire email header.
   
2. **Analyze the Header in AladdinX**:  
   - Paste the copied header into the provided input field on the web interface.
   - Click **Genie Boom** to get detailed information about the email’s security risks.

---

## 🌍 Deploy in Your Infrastructure

If you want to deploy AladdinX in your infrastructure, follow these steps:

1. **Clone the repo**:
    ```bash
    git clone https://github.com/Muhammad-Shaheer-khan/AladdinX.git
    ```
2. **Install dependencies** using `requirements.txt`.
3. **Add API keys** for VirusTotal, IPGeolocation, and Gemini (refer to the "Installation" section).
4. **Run the application** locally or deploy it on your server.

For further help with deployment, feel free to reach out, and I'll guide you through the process! 😊

---

## 🛠️ Development and Contributions

### How to contribute:
If you'd like to contribute or feature your logo in the project, please send an email to `shaheerk2233@gmail.com` with the following details:
- **Company Name**: [Your Company Name]
- **Email**: [Your Contact Email]
- **Logo URL**: [Link to Your Logo]
- **Description**: [Brief Description of Your Contribution]

Your logo will be displayed on the front page of the email analyzer. 🌟

---

## 💖 Support

If you like the project and want to support me, you can **buy me a coffee** via **Nayapay**! ☕

💳 **Buy a Coffee**:  
Account Name: M Shaheer khan  
Account Number: 4782 7800 2261 9160

---

## 📝 License

This project is open-source and licensed under the [MIT License](LICENSE).

---

## 📬 Contact

- **GitHub**: [Muhammad-Shaheer-khan](https://github.com/Muhammad-Shaheer-khan)
- **Email**: [shaheerk2233@gmail.com](mailto:shaheerk2233@gmail.com)
- **LinkedIn**: [Muhammad Shaheer Khan](https://www.linkedin.com/in/muhammad-shaheer-khan)

Feel free to reach out for collaborations, queries, or feedback!

---

### 💡 Note:
- **UI Issues**: Just leave a note if you find any UI issue or any kind of UI functionality problem. Please do not treat it as a UI developer issue. The UI may not be perfect yet, but the core functionality is working. 🔧

---

Happy analyzing with AladdinX! ✨🧑‍💻
