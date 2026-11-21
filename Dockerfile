FROM python:3.12-slim

# Install uv for fast dependency management
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

# Copy dependency files first to leverage Docker layer caching
COPY pyproject.toml uv.lock ./

# Install dependencies into the system environment
RUN uv sync --frozen --no-dev

# Copy the rest of the project files
COPY . .

# Ensure logs and data directories exist
RUN mkdir -p logs data

# Expose the Flask dashboard port
EXPOSE 5000

# Run the Web UI by default
CMD ["uv", "run", "python", "ui/app.py"]