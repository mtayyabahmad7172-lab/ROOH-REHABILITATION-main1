import multiprocessing
import os

# Bind to PORT provided by Render
bind = f"0.0.0.0:{os.environ.get('PORT', '10000')}"

# Worker configuration
workers = 2  # Increased to 2 for better performance, but keep low for memory safety on free tier
worker_class = "sync"
worker_connections = 1000
timeout = 120  # Increased timeout for MongoDB cold starts
keepalive = 5

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "info"

# Graceful timeout
graceful_timeout = 30

# Preload app to save memory
preload_app = True

# Max requests per worker before restart (prevent memory leaks)
max_requests = 1000
max_requests_jitter = 100
