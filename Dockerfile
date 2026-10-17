# Use a specific Python image version (if compatible)
FROM python:3.11

# Set the working directory
WORKDIR /app

# Copy oonidata and oonipipeline source files into the container
COPY oonidata ./oonidata
COPY oonipipeline ./oonipipeline

# Install dependencies for both projects
RUN pip install ./oonidata && pip install ./oonipipeline

# Set the default command for the container
CMD ["/bin/bash"]
