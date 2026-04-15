# Use a specific Python image version (if compatible)
FROM python:3.11

# Set the working directory
WORKDIR /app

# Copy oonidata and oonipipeline source files into the container
COPY ./tests ./app

# Install dependencies for both projects
RUN pip install pytest httpx jwt requests

# Set the default command for the container
CMD ["/bin/bash"]
