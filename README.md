# Rooh Rehabilitation Center - Patient Management System (RoohPMS)

RoohPMS is a comprehensive Patient Management System (PMS) designed for the **Rooh Rehabilitation Center**. It streamlines hospital operations, patient care, and financial management for addiction treatment and psychological services.

## 🚀 Key Features

### 🏥 Patient Management
- **Admissions**: Efficient patient onboarding with photo uploads and detailed profile creation.
- **Patient Directory**: Track active and discharged patients with search and filter capabilities.
- **Medical Records**: Manage prescriptions, psychological session notes, and medical history.
- **Discharge Workflow**: Automated discharge slip generation with billing summaries.

### 💰 Financial & Overhead Management
- **Comprehensive Expense Tracking**: Log incoming fees and outgoing operational costs.
- **Utility Bill Management**: Track pending bills (Electricity, Gas, Internet, Rent) with due dates.
- **Monthly Overheads Dashboard**: Admin-only view for profit/loss calculation and financial projections.
- **Recovery Tracking**: Manage outstanding balances and commitment dates for old records.

### 👥 HR & Operations
- **Staff Management**: Maintain employee profiles, designations, and contact info.
- **Attendance Tracking**: Monthly attendance management with printable reports.
- **Payroll**: Track salaries, advances, and remaining payments.

### 📊 Reporting & Analytics
- **KPI Dashboard**: Real-time metrics for occupancy, cash flow, and occupancy rates.
- **Data Export**: Export patient records and financial data to Excel for external reporting.

## 🛠️ Technology Stack

- **Backend**: Python / Flask
- **Database**: MongoDB (NoSQL)
- **Frontend**: HTML5, Tailwind CSS, JavaScript (Vanilla)
- **Reporting**: Pandas & OpenPyXL for Excel exports
- **Authentication**: Role-based access control (Admin/Staff), Password Reset via Gmail SMTP

## ⚙️ Local Setup

### Prerequisites
- Python 3.8+
- MongoDB (running locally or a cloud instance like MongoDB Atlas)

### Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd RoohPMS
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure Environment Variables**:
   Create a `.env` file in the root directory (refer to `.env.example`):
   ```env
   MONGO_URI=mongodb://localhost:27017/rooh_pms
   SECRET_KEY=your_secret_key_here
   GMAIL_USER=your-email@gmail.com
   GMAIL_APP_PASSWORD=your-app-password
   ADMIN_EMAIL=admin@roohrehab.com
   ```

4. **Run the application**:
   ```bash
   python app.py
   ```

5. **Access the application**:
   Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.

## 🛡️ Security
- **Authentication**: Secure login with hashed passwords.
- **Roles**: 
  - `Admin`: Full access to financial overheads and user management.
  - `Staff`: Access to patient records and daily operational tasks.

## 🎨 Branding
The application has been recently rebranded from the internal "PRO" designation to the official **Rooh** branding, featuring a professional UI with the gold and green theme of Rooh Rehabilitation Center.

---
© 2026 Rooh Rehabilitation Center. All rights reserved.
