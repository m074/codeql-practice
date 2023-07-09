import aiohttp

async with aiohttp.ClientSession(verify_ssl=False) as session:
    async with session.get('https://example.com') as response:
        print(response.status)