# Wallet System with UPI Integration

A simple wallet system that allows users to deposit and withdraw money using UPI payments. The system includes both user and admin interfaces.

## Features

- User Registration and Login
- Wallet Balance Management
- UPI-based Deposits with QR Code Generation
- Withdrawal Requests with UPI ID
- Admin Panel for Transaction Approval
- Transaction History

## Setup Instructions

1. Install Python 3.7 or higher if not already installed

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Update the UPI ID:
Open `app.py` and replace `"your-upi-id@upi"` with your actual UPI ID.

5. Run the application:
```bash
python app.py
```

6. Access the application:
- Open http://localhost:5000 in your web browser
- Register a new user account
- For admin access, manually set is_admin=True in the database for your user

## Directory Structure

```
.
├── app.py              # Main application file
├── requirements.txt    # Python dependencies
├── static/            # Static files
│   ├── screenshots/   # Uploaded payment screenshots
│   └── qr_codes/     # Uploaded UPI QR codes
└── templates/         # HTML templates
```

## Usage

### For Users
1. Register/Login to your account
2. To deposit:
   - Enter the amount
   - Scan the generated QR code
   - Make the payment
   - Upload payment screenshot
3. To withdraw:
   - Enter amount and UPI details
   - Upload your UPI QR code
   - Wait for admin approval

### For Admins
1. Login to an admin account
2. Access Admin Panel
3. Review pending transactions
4. Approve/Reject transactions

## Security Notes

- Always verify payment screenshots before approving transactions
- Double-check UPI IDs for withdrawals
- Never share your admin credentials
- Keep your secret key secure 