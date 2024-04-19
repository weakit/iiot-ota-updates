# Secure OTA Updates
### CS21B1041

This is a sample implementation of a OTA Updates system that was designed and made for a college course:   
CS5005 IIoT and Cloud Computing.

This project consists of a server and a client.

### Server side programs

`update.py` will package and make a deployment in the same folder.   
`server.py` will serve the deplpoyments on a HTTP server.   
`keys.py` will generate a new RSA key pair.

### Client side programs

`run.py` will ensure the latest version available is being run.
