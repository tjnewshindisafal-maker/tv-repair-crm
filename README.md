# TV Repair CRM

A simple multi-location CRM for TV/appliance repair businesses — track leads/calls (with source: Google Ads, GMB, MyOperator, walk-in, referral), manage repair jobs end-to-end, and see location-wise conversion stats.

## Features

- **Auth** — signup/login with JWT + bcrypt.
- **Locations** — manage your shop branches.
- **Leads / Calls** — log every enquiry with name, phone, location and source; track status (New → Contacted → Converted → Lost); import call logs in bulk from a CSV export (e.g. MyOperator).
- **Jobs** — create a repair job, assign a technician, update status, set cost.
- **Technicians** — manage your repair staff.
- **Customers** — auto-aggregated customer history from job records.

## Setup

```bash
npm install
cp .env.example .env   # fill in MONGO_URI and JWT_SECRET
npm start
```

Open `http://localhost:3000`, create an account, and start adding your locations and leads.
