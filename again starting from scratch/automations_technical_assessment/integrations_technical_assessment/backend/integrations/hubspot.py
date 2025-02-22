# slack.py

from fastapi import Request
from redis_client import add_key_value_redis , get_value_redis, delete_key_redis
from fastapi import HTTPException
import httpx
import asyncio
from fastapi.responses import HTMLResponse
import json
import secrets
import os
import base64
from .integration_item import IntegrationItem
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Allow frontend (localhost:3000) to access the backend (localhost:8000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Allow requests from React frontend
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)
@app.get("/")  
async def root():  
    return {"message": "FastAPI is running!"}

CLIENT_ID = 'bdab83ae-4b61-4e26-986e-764aed0d2841'
CLIENT_SECRET = '2470a265-3432-4b49-96b8-2a4251f91df2'
encoded_client_id_secret = base64.b64encode(f'{CLIENT_ID}:{CLIENT_SECRET}'.encode()).decode()

REDIRECT_URI = 'http://localhost:8000/integrations/hubspot/oauth2callback'
authorization_url = f'https://app.hubspot.com/oauth/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope=crm.objects.contacts.write%20oauth%20crm.objects.contacts.read'

async def authorize_hubspot(user_id, org_id):
    state_data = {
        'state': secrets.token_urlsafe(32),
        'user_id': user_id,
        'org_id': org_id
    }
    print('---------state_data--------- ', state_data)
    encoded_state = json.dumps(state_data)
    print('---------encoded_state--------- ', encoded_state)
    await add_key_value_redis(f'hubspot_state:{org_id}:{user_id}', encoded_state, expire=600)

    return {"auth_url": f'{authorization_url}&state={encoded_state}'}

async def oauth2callback_hubspot(request: Request):
    if request.query_params.get('error'):
        raise HTTPException(status_code=400, detail=request.query_params.get('error'))
    code = request.query_params.get('code')
    encoded_state = request.query_params.get('state')
    state_data = json.loads(encoded_state)

    original_state = state_data.get('state')
    user_id = state_data.get('user_id')
    org_id = state_data.get('org_id')

    saved_state = await get_value_redis(f'hubspot_state:{org_id}:{user_id}')

    if not saved_state or original_state != json.loads(saved_state).get('state'):
        raise HTTPException(status_code=400, detail='State does not match.')

    async with httpx.AsyncClient() as client:
        response, _ = await asyncio.gather(
            client.post(
                'https://api.hubapi.com/oauth/v1/token',
                data={
                    'grant_type': 'authorization_code',
                    'code': code,
                    'redirect_uri': REDIRECT_URI,
                    'client_id': CLIENT_ID,   
                    'client_secret': CLIENT_SECRET
                }, 
                headers={
                    'Authorization': f'Basic {encoded_client_id_secret}',
                    'Content-Type': 'application/x-www-form-urlencoded',
                }
            ),
            delete_key_redis(f'hubspot_state:{org_id}:{user_id}'),
        )

    await add_key_value_redis(f'hubspot_credentials:{org_id}:{user_id}', json.dumps(response.json()), expire=600)
    
    close_window_script = """
    <html>
        <script>
            window.close();
        </script>
    </html>
    """
    return HTMLResponse(content=close_window_script)


async def get_hubspot_credentials(user_id, org_id):
    credentials = await get_value_redis(f'hubspot_credentials:{org_id}:{user_id}')
    if not credentials:
        raise HTTPException(status_code=400, detail='No credentials found.')
    credentials = json.loads(credentials)
    if not credentials:
        raise HTTPException(status_code=400, detail='No credentials found.')
    await delete_key_redis(f'hubspot_credentials:{org_id}:{user_id}')

    return credentials

async def create_integration_item_metadata_object(response_json):
    # TODO
    pass

async def get_items_hubspot(credentials):
    """Fetch HubSpot items (e.g., contacts) using the stored access token."""
    credentials = json.loads(credentials)
    access_token = credentials.get("access_token")
    
    if not access_token:
        raise HTTPException(status_code=400, detail='No access token found.')

    async with httpx.AsyncClient() as client:
        response = await client.get(
            'https://api.hubapi.com/crm/v3/objects/contacts',
            headers={'Authorization': f'Bearer {access_token}'}
        )

    if response.status_code == 200:
        results = response.json()['results']
        list_of_integration_items = []
        for result in results:
            properties = result.get('properties', {})
            list_of_integration_items.append(
                IntegrationItem(
                    id=result['id'],
                    type='contact',
                    name=properties.get('firstname', 'No Name'),
                    creation_time=properties.get('createdate', 'Unknown'),
                    last_modified_time=properties.get('lastmodifieddate', 'Unknown'),
                    parent_id=None 
                )
            )

        print(list_of_integration_items)
        return list_of_integration_items
    else:
        raise HTTPException(status_code=response.status_code, detail='Failed to retrieve HubSpot items.')