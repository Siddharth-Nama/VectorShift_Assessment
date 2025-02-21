from redis_client import get_value_redis, delete_key_redis
import json
from fastapi import HTTPException

close_window_script = """
    <html>
        <script>
            window.close();
        </script>
    </html>
"""


async def fetch_credentials(service:str, org_id: str, user_id: str):
    credentials = await get_value_redis(f'{service}_credentials:{org_id}:{user_id}')
    if not credentials:
        raise HTTPException(status_code=400, detail='No credentials found.')
    credentials = json.loads(credentials)
    await delete_key_redis(f'{service}_credentials:{org_id}:{user_id}')
    return credentials