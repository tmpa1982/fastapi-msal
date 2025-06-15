from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import base64
import json

app = FastAPI()

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

@app.get("/")
def read_root():
    return {"message": "Hello, World!"}

def parse_client_principal(request: Request):
    header = request.headers.get("X-MS-CLIENT-PRINCIPAL")
    if not header:
        raise HTTPException(status_code=401, detail="Not authenticated")
    decoded = base64.b64decode(header)
    principal = json.loads(decoded)
    return principal

@app.get("/secure-endpoint")
async def secure_endpoint(request: Request):
    user = parse_client_principal(request)
    return {"user": user}

def extract_claim(claims, claim_type):
    for claim in claims:
        if claim["typ"] == claim_type:
            return claim["val"]
    return None

@app.get("/whoami")
async def whoami(request: Request):
    user = parse_client_principal(request)
    name = extract_claim(user["claims"], "name")
    email = extract_claim(user["claims"], "preferred_username")
    roles = [c["val"] for c in user["claims"] if c["typ"] == "roles"]
    return {"name": name, "email": email, "roles": roles}
