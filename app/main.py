from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt, JWTError
import httpx

app = FastAPI()
security = HTTPBearer()

TENANT_ID = "aa76d384-6e66-4f99-acef-1264b8cef053"
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
JWKS_URL = f"{AUTHORITY}/discovery/v2.0/keys"
AUDIENCE = "api://cc71daca-4e96-4575-b8be-107360a7031b"
ISSUER = f"https://sts.windows.net/{TENANT_ID}/"

origins = [
    "http://localhost:5173",  # Vite dev server
    "https://tmpa-vite-msal.azurewebsites.net",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Cache for public keys
jwks = None

async def get_public_keys():
    global jwks
    if jwks is None:
        async with httpx.AsyncClient() as client:
            resp = await client.get(JWKS_URL)
            resp.raise_for_status()
            jwks = resp.json()
    return jwks

async def verify_token(auth: HTTPAuthorizationCredentials = Depends(security)):
    token = auth.credentials
    keys = await get_public_keys()
    try:
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header["kid"]
        key = next((k for k in keys["keys"] if k["kid"] == kid), None)
        if not key:
            raise HTTPException(status_code=401, detail="Public key not found.")
        payload = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=AUDIENCE,
            issuer=ISSUER,
        )
        return payload
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")

def check_role(required_role: str):
    async def role_checker(payload: dict = Depends(verify_token)):
        roles = payload.get("roles", [])
        if required_role not in roles:
            raise HTTPException(status_code=403, detail=f"Missing role: {required_role}")
        return payload
    return role_checker

@app.get("/")
def read_root():
    return {"message": "Hello, World!"}

@app.get("/whoami")
async def whoami(payload: dict = Depends(verify_token)):
    return {
        "sub": payload["sub"],
        "name": payload.get("name"),
        "email": payload.get("email"),
        "roles": payload.get("roles", []),
        "claims": payload,
    }

@app.get("/read-data")
async def read_data(payload: dict = Depends(check_role("READ"))):
    return {"message": "You have READ access."}

@app.post("/write-data")
async def write_data(payload: dict = Depends(check_role("WRITE"))):
    return {"message": "You have WRITE access."}
