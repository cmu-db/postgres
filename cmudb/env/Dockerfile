# NoisePage officially supports Ubuntu 20.04.
FROM ubuntu:20.04
# The default argument for docker run is bash.
CMD ["bash"]

# Suppress interactive dialog.
ARG DEBIAN_FRONTEND=noninteractive

# Install packages.
RUN apt-get -y update
RUN apt-get -y install sudo
COPY ./cmudb/env/packages.sh install-script.sh
RUN echo y | ./install-script.sh all

# Create a non-sudo user.
RUN adduser --disabled-password --gecos '' dev \
    && adduser dev sudo \
    && echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
USER dev
WORKDIR /home/dev

# Copy the contents of the build context (working directory).
COPY . /home/dev/repo
