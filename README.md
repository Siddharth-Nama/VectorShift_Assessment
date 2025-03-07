# VectorShift Integrations Technical Assessment

## Candidate Introduction
I am a passionate software developer with expertise in full-stack development, competitive programming, and problem-solving. With hands-on experience in JavaScript, React, Python, and FastAPI, i am adept at building scalable applications and integrating APIs. I have worked on various web and backend projects, demonstrating strong analytical skills and a keen interest in software architecture and integrations.

## Overview
This repository contains the solution to the VectorShift Integrations Technical Assessment. The implementation involves integrating HubSpot OAuth authentication into a FastAPI backend and a React frontend, as well as fetching and displaying HubSpot data.

## Tech Stack
- **Frontend:** React, JavaScript
- **Backend:** FastAPI, Python
- **Database & Caching:** Redis

## Setup Instructions
### Prerequisites
Ensure you have the following installed:
- Node.js and npm
- Python 3.8+
- Redis

### Installation
#### Backend
1. Navigate to the backend folder:
   ```sh
   cd backend
   ```
2. Create and activate a virtual environment:
   ```sh
   python -m venv venv
   source venv/bin/activate  # On Windows use: venv\Scripts\activate
   ```
3. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```
4. Start Redis server:
   ```sh
   redis-server
   ```
5. Run the FastAPI backend:
   ```sh
   uvicorn main:app --reload
   ```

#### Frontend
1. Navigate to the frontend directory:
   ```sh
   cd frontend
   ```
2. Install dependencies:
   ```sh
   npm install
   ```
3. Start the React application:
   ```sh
   npm run start
   ```

## Implementation Details

### Part 1: HubSpot OAuth Integration
- Implemented OAuth authentication flow for HubSpot in `backend/integrations/hubspot.py`.
- Functions implemented:
  - `authorize_hubspot`: Redirects users to the HubSpot OAuth consent screen.
  - `oauth2callback_hubspot`: Handles the callback, exchanges the authorization code for an access token.
  - `get_hubspot_credentials`: Retrieves and refreshes stored credentials.
- Created a corresponding frontend integration in `frontend/src/integrations/hubspot.js`.
- Added UI components for HubSpot authentication in the existing integrations UI.

### Part 2: Loading HubSpot Items
- Implemented `get_items_hubspot` in `backend/integrations/hubspot.py` to fetch HubSpot data.
- Decided on key fields to retrieve from HubSpot’s API (e.g., Contacts, Deals, Companies).
- Retrieved data is formatted into `IntegrationItem` objects.
- Data is printed to the console for validation.

## Testing
- Create a HubSpot app and generate `client_id` and `client_secret`.
- Update environment variables or config files with the credentials.
- Run the frontend and backend servers.
- Test authentication and data retrieval via console logs.

## Future Improvements
- Enhance UI to display fetched HubSpot items dynamically.
- Improve error handling and logging.
- Store tokens securely using a database instead of in-memory storage.

## Contact
For any questions, reach out to `siddharthnama.work@gmail.com`.

---
This repository successfully integrates HubSpot OAuth and fetches HubSpot data as per the assessment requirements.