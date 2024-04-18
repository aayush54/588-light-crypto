# ROS Encrypt / Decrypt Package

## Welcome

This is the repo for our EECS 588 project. This package is designed as a catkin package for ROS-noetic. 

## Quickstart

Assuming you already have an existing repo, this repo can be cloned and built using `catkin build`. Full setup requires installing `ros-noetic`, `catkin`, and other required packages. One guide is here: [ROS + Catkin Setup](https://github.com/Intelligent-Quads/iq_tutorials/blob/master/docs/installing_ros_20_04.md). We also provide a barebones Dockerfile that matches the submarine setup. 

For integration into an existing repo, the main task is to change the string definitions under the `Payload` template in `crypto_helpers.h`. These define the channels that should be encrypted and decrypted. Then, existing nodes can simply listen to the outputs from the decrypted nodes which are under `/plaintext`. 

We also include the launch file `crypto.launch` for convenience which launches both nodes together. 


## Contributions

Our contributions are formatted as a catkin package meant to easily be integrated into any existing ROS system. 

The `src` directory contains our main code contributions. We also include the `ascon_c` and `openssl-cmake` folders for convenience with building these crypto libraries. We've designed an encrypt and decrypt node, written in `encrypt_teleop.cpp` and `decrypt_teleop.cpp`. We also include ascon and openssl wrappers meant to be interchangeable into the nodes. 