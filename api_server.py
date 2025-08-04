# api_server.py

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from click.testing import CliRunner
import subprocess
import main as cli_main  # This imports your existing CLI app

app = FastAPI()

# Enable CORS for frontend requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust this in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class QueryInput(BaseModel):
    query: str

@app.post("/process_query")
async def process_query(input_data: QueryInput):
    runner = CliRunner()

    try:
        # Execute the CLI app as if called from terminal
        result = runner.invoke(cli_main.main, [
            "--query", input_data.query,
            "--format", "json",  # You can change output type if needed
            "--ai-provider", "gemini"  # Optional: set provider
        ])

        if result.exit_code != 0:
            return {
                "success": False,
                "command": input_data.query,
                "error": result.stderr or "An error occurred during execution",
                "data": result.output
            }

        return {
            "success": True,
            "command": input_data.query,
            "data": result.output
        }

    except Exception as e:
        return {
            "success": False,
            "command": input_data.query,
            "error": str(e),
            "data": None
        }
