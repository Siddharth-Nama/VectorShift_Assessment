# slack.py

import asyncio
import httpx
from fastapi.responses import HTMLResponse
from fastapi import HTTPException
import secrets
import json
import os
from redis_client import add_key_value_redis, delete_key_redis, get_value_redis
from integrations.utils import close_window_script, fetch_credentials
from fastapi import Request
from dotenv import load_dotenv
import requests
from integrations.integration_item import IntegrationItem
load_dotenv()

CLIENT_ID = os.environ.get('HUBSPOT_CLIENT_ID')
CLIENT_SECRET = os.environ.get('HUBSPOT_CLIENT_SECRET')
REDIRECT_URI = f"{os.environ.get('ROOT_DOMAIN')}/integrations/hubspot/oauth2callback"
scope = os.environ.get('HUBSPOT_OAUTH_SCOPE')
authorization_url = f"https://app.hubspot.com/oauth/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={scope}"


async def authorize_hubspot(user_id, org_id):
    state_data = {
        'state': secrets.token_urlsafe(32),
        'user_id': user_id,
        'org_id': org_id
    }
    encoded_state = json.dumps(state_data)
    await add_key_value_redis(f'hubspot_state:{org_id}:{user_id}', encoded_state, expire=600)
    return f'{authorization_url}&state={encoded_state}'


async def oauth2callback_hubspot(request: Request):
    if request.query_params.get('error'):
        raise HTTPException(
            status_code=400, detail=request.query_params.get('error'))
    code = request.query_params.get('code')
    encoded_state = request.query_params.get('state')
    state_data = json.loads(encoded_state)

    original_state = state_data.get('state')
    user_id = state_data.get('user_id')
    org_id = state_data.get('org_id')

    saved_state = await get_value_redis(f'hubspot_state:{org_id}:{user_id}')

    if not saved_state or original_state != json.loads(saved_state).get('state'):
        raise HTTPException(status_code=400, detail='Please login again')

    async with httpx.AsyncClient() as client:
        response, _ = await asyncio.gather(
            client.post(
                'https://api.hubapi.com/oauth/v1/token',
                headers={
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                data={
                    'grant_type': 'authorization_code',
                    'code': code,
                    'redirect_uri': REDIRECT_URI,
                    'client_secret': CLIENT_SECRET,
                    'client_id': CLIENT_ID
                }
            ),
            delete_key_redis(f'hubspot_state:{org_id}:{user_id}'),
        )
    await add_key_value_redis(f'hubspot_credentials:{org_id}:{user_id}', json.dumps(response.json()), expire=600)

    return HTMLResponse(content=close_window_script)


async def get_hubspot_credentials(user_id, org_id):
    return await fetch_credentials('hubspot', user_id=user_id, org_id=org_id)


def create_integration_item_metadata_object(response_json) -> IntegrationItem:
    integration_item_metadata = IntegrationItem(
        id=response_json['listId'],
        type=response_json['objectTypeId'],
        name=response_json['objectTypeId'],
        creation_time=response_json['createdAt'],
        last_modified_time=response_json['updatedAt'],
    )

    return integration_item_metadata


def get_items_hubspot_api(url, access_token):
    return requests.get(
        url=url,
        headers={
            'Authorization': f'Bearer {access_token}'},
    )


async def get_items_hubspot(credentials):
    """Get first 20 lists in app. All Lists API not available"""
    credentials = json.loads(credentials)
    url = 'https://api.hubapi.com/crm/v3/lists/?'
    for i in range(1, 21):
        url += f'listIds={i}&'
    lists_response = None
    lists_response = get_items_hubspot_api(
        url, credentials.get('access_token'))
    if lists_response.status_code == 401 and lists_response.json()['category'] == 'EXPIRED_AUTHENTICATION':
        # Handling expiry of access token
        new_token_response = requests.post(
            url='https://api.hubapi.com/oauth/v1/token',
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            data={
                'grant_type': 'refresh_token',
                'redirect_uri': REDIRECT_URI,
                'client_secret': CLIENT_SECRET,
                'client_id': CLIENT_ID,
                'refresh_token': credentials.get("refresh_token")
            },
        )
        lists_response = get_items_hubspot_api(
            url, new_token_response.json()["access_token"])
    list_of_integration_item_metadata = []
    for list in lists_response.json()['lists']:
        list_of_integration_item_metadata.append(
            create_integration_item_metadata_object(list))
    return list_of_integration_item_metadata
